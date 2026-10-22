"""agent.py - orchestration layer: MCP client, LLM tool loop, guardrails, confirmation (sections 3.2, 3.3)."""
import asyncio
import json
import os
import re
import shlex
import sys
import time
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from typing import Callable

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from pydantic import ValidationError

import backend
from guardrails import GuardrailError, LockoutError, check_argv, check_rule, is_high_risk
from rules import DeleteRequest, RuleRequest, build_argv, format_rules

SYSTEM_PROMPT = """You are Agent 18, a Linux firewall assistant. You manage ONLY the IPv4 iptables firewall (INPUT and OUTPUT chains) through the tools provided.
Rules:
- Use only the listed tools. Never invent tool names and never write shell commands.
- If the request is not about firewall rules (deleting files, running commands, rebooting, and so on), do not call any tool. Say that you only manage firewall rules.
- You cannot flush the firewall or change default policies. Say so instead of trying.
- "Incoming" means direction "in" and "outgoing" means "out". "Anywhere" or "everyone" means source 0.0.0.0/0.
- Call lookup_service_port when the user names a service (ssh, http, https, ...) instead of a port number.
- Before deleting a rule, or when asked whether a rule or port is open, call list_firewall_rules. Delete uses the rule number from that list.
- When a request has an exception, emit the specific ACCEPT rule and the broad DROP rule as two add_firewall_rule calls.
- If the source address or the port is unclear, ask the user a short question instead of guessing.
- After the tool results arrive, answer in one or two short sentences.
Example: "Stop 10.0.0.7 reaching my web server" -> add_firewall_rule(protocol="tcp", port=80, source="10.0.0.7", action="DROP", direction="in")"""

READ_TOOLS = {"get_firewall_status", "list_firewall_rules", "lookup_service_port"}
WRITE_TOOLS = {"add_firewall_rule", "delete_firewall_rule", "undo_last_change"}
HERE = os.path.dirname(os.path.abspath(__file__))


# -- LLM clients ---------------------------------------------------------------------------------
@dataclass
class ToolCall:
    name: str
    arguments: dict


@dataclass
class LLMReply:
    content: str
    tool_calls: list[ToolCall]
    fallback: bool = False      # the call was recovered from JSON text in the message body

    def as_message(self) -> dict:
        msg = {"role": "assistant", "content": self.content}
        if self.tool_calls:
            msg["tool_calls"] = [{"function": {"name": c.name, "arguments": c.arguments}} for c in self.tool_calls]
        return msg


def parse_inline_calls(content: str) -> list[ToolCall]:
    """JSON enforcement: some models print the call as text instead of using the tool-call channel."""
    text = content.strip()
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text)
    try:
        data = json.loads(text)
    except ValueError:
        return []
    items = data if isinstance(data, list) else [data]
    calls = []
    for item in items:
        if isinstance(item, dict) and "name" in item and isinstance(item.get("parameters", item.get("arguments", {})), dict):
            calls.append(ToolCall(str(item["name"]), item.get("parameters", item.get("arguments", {}))))
        else:
            return []
    return calls


class OllamaLLM:
    def __init__(self, model: str = "llama3.1:8b", host: str | None = None, num_ctx: int = 4096):
        import ollama
        self.model = model
        self.num_ctx = num_ctx
        self.client = ollama.Client(host=host or os.environ.get("OLLAMA_HOST", "http://localhost:11434"), timeout=600)

    def chat(self, messages: list[dict], tools: list[dict]) -> LLMReply:
        resp = self.client.chat(model=self.model, messages=messages, tools=tools, keep_alive="60m",
                                options={"temperature": 0, "seed": 7, "num_ctx": self.num_ctx})
        msg = resp.message
        calls = [ToolCall(c.function.name, dict(c.function.arguments or {})) for c in (msg.tool_calls or [])]
        content = msg.content or ""
        if not calls:
            inline = parse_inline_calls(content)
            if inline:
                return LLMReply("", inline, fallback=True)
        return LLMReply(content, calls)


class LlamaCppLLM:
    """Local GGUF model through llama-cpp-python, used when Ollama is unavailable (same tool-calling interface)."""
    def __init__(self, path: str, n_ctx: int = 4096, n_threads: int = 8):
        from llama_cpp import Llama
        self.llm = Llama(model_path=path, n_ctx=n_ctx, n_threads=n_threads, verbose=False,
                         chat_format="chatml-function-calling")

    @staticmethod
    def _to_openai(messages: list[dict]) -> list[dict]:
        out, pending, n = [], [], 0
        for m in messages:
            if m["role"] == "assistant" and m.get("tool_calls"):
                calls = []
                for c in m["tool_calls"]:
                    n += 1
                    cid = f"call_{n}"
                    pending.append(cid)
                    calls.append({"id": cid, "type": "function",
                                  "function": {"name": c["function"]["name"],
                                               "arguments": json.dumps(c["function"]["arguments"])}})
                out.append({"role": "assistant", "content": None, "tool_calls": calls})
            elif m["role"] == "tool":
                out.append({"role": "tool", "tool_call_id": pending.pop(0) if pending else "call_0",
                            "name": m.get("tool_name", ""), "content": m["content"]})
            else:
                out.append({"role": m["role"], "content": m["content"]})
        return out

    def chat(self, messages: list[dict], tools: list[dict]) -> LLMReply:
        out = self.llm.create_chat_completion(messages=self._to_openai(messages), tools=tools, tool_choice="auto",
                                              temperature=0, seed=7, max_tokens=400)
        msg = out["choices"][0]["message"]
        calls = []
        for tc in msg.get("tool_calls") or []:
            try:
                args = json.loads(tc["function"]["arguments"] or "{}")
            except ValueError:
                args = {"_unparsed": tc["function"]["arguments"]}
            calls.append(ToolCall(tc["function"]["name"], args if isinstance(args, dict) else {}))
        content = (msg.get("content") or "")
        if not calls:
            inline = parse_inline_calls(content)
            if inline:
                return LLMReply("", inline, fallback=True)
        return LLMReply(content, calls)


class StubLLM:
    """Echoes the last user message; used to test the REPL without a model (Step 1)."""
    def chat(self, messages: list[dict], tools: list[dict]) -> LLMReply:
        last = next(m["content"] for m in reversed(messages) if m["role"] == "user")
        return LLMReply(f"[stub] received: {last}", [])


# -- results -------------------------------------------------------------------------------------
@dataclass
class Valid:
    name: str
    obj: object
    norm: tuple


@dataclass
class Result:
    prompt: str
    text: str = ""
    table: str = ""
    model_calls: list = field(default_factory=list)        # normalised valid tool calls
    invalid: list = field(default_factory=list)            # invalid model outputs and their errors
    confirm_requests: list = field(default_factory=list)   # command lists shown to the user
    refused: str = ""
    declined: bool = False
    changed: bool = False
    rolled_back: bool = False
    failed: bool = False
    capped: bool = False
    retries: int = 0
    turns: int = 0
    llm_times: list = field(default_factory=list)
    confirm_wait: float = 0.0
    t_first_tool: float | None = None     # seconds from Enter to the first tool call, minus confirmation wait
    t_first_write: float | None = None    # seconds from Enter to the first changing call, minus confirmation wait
    t_total: float = 0.0

    def output(self) -> str:
        return self.text + (("\n\n" + self.table) if self.table else "")


@dataclass
class Ctx:
    listed: bool = False
    deletes: int = 0


def _short(err: ValidationError) -> str:
    parts = []
    for e in err.errors():
        loc = ".".join(str(x) for x in e["loc"]) or "arguments"
        parts.append(f"{loc}: {e['msg']}")
    return "; ".join(parts)


# -- the agent -----------------------------------------------------------------------------------
class FirewallAgent:
    def __init__(self, confirm: Callable[[str, list, bool], bool], override: Callable[[str], bool] | None = None,
                 llm=None, max_turns: int = 5, max_retries: int = 2, history_len: int = 3):
        self.confirm = confirm
        self.override = override
        self.llm = llm
        self.max_turns = max_turns
        self.max_retries = max_retries
        self.history_len = history_len
        self.history: list[tuple[str, str]] = []
        self.last_batch = 0
        self._stack = AsyncExitStack()

    async def __aenter__(self):
        params = StdioServerParameters(command=sys.executable, args=[os.path.join(HERE, "firewall_server.py")],
                                       env=dict(os.environ), cwd=HERE)
        read, write = await self._stack.enter_async_context(stdio_client(params))
        self.session = await self._stack.enter_async_context(ClientSession(read, write))
        await self.session.initialize()
        tools = (await self.session.list_tools()).tools
        self.tools = {t.name: t for t in tools}
        self.llm_tools = [self._model_schema(t) for t in tools]
        return self

    async def __aexit__(self, *exc):
        await self._stack.aclose()

    @staticmethod
    def _model_schema(tool) -> dict:
        params = json.loads(json.dumps(tool.inputSchema))
        if tool.name == "add_firewall_rule":
            params.get("properties", {}).pop("position", None)     # the client chooses rule positions
        return {"type": "function", "function": {"name": tool.name, "description": tool.description, "parameters": params}}

    # -- helpers ---------------------------------------------------------------------------------
    async def _call(self, res: Result, t0: float, name: str, args: dict) -> str:
        now = time.perf_counter() - t0 - res.confirm_wait
        if res.t_first_tool is None:
            res.t_first_tool = now
        if name in WRITE_TOOLS and res.t_first_write is None:
            res.t_first_write = now
        result = await self.session.call_tool(name, args)
        text = "".join(getattr(c, "text", "") for c in result.content)
        if result.isError:
            raise RuntimeError(text or "tool error")
        return text

    async def _list(self, res: Result, t0: float, chain: str = "INPUT") -> list[dict]:
        return json.loads(await self._call(res, t0, "list_firewall_rules", {"chain": chain}))["rules"]

    @staticmethod
    def _compact(chain: str, rules: list[dict]) -> str:
        if not rules:
            return f"{chain} has no rules."
        return f"{chain} rules: " + "; ".join(
            f"[{r['number']}] {r['action']} {r['protocol']} port {r['port'] or 'any'} from {r['source']}" for r in rules)

    def _validate(self, call: ToolCall) -> Valid:
        if call.name not in self.tools:
            raise ValueError(f"unknown tool {call.name!r}; the available tools are: {', '.join(sorted(self.tools))}")
        args = dict(call.arguments or {})
        try:
            if call.name == "add_firewall_rule":
                args.pop("position", None)
                rule = RuleRequest(**args)
                return Valid(call.name, rule, (call.name, rule.protocol, rule.port, rule.source, rule.action, rule.direction))
            if call.name == "delete_firewall_rule":
                req = DeleteRequest(**args)
                return Valid(call.name, req, (call.name, req.chain, req.rule_number))
            if call.name == "list_firewall_rules":
                chain = DeleteRequest(chain=args.get("chain", "INPUT"), rule_number=1).chain
                return Valid(call.name, chain, (call.name,))
            if call.name == "lookup_service_port":
                name = str(args.get("name", "")).strip()
                if not re.fullmatch(r"[A-Za-z0-9-]{1,32}", name):
                    raise ValueError("name must be a service name such as ssh or https")
                return Valid(call.name, name, (call.name,))
        except ValidationError as err:
            raise ValueError(_short(err))
        return Valid(call.name, None, (call.name,))

    # -- the request loop ------------------------------------------------------------------------
    async def handle(self, prompt: str) -> Result:
        res = Result(prompt=prompt)
        ctx = Ctx()
        t0 = time.perf_counter()
        messages = [{"role": "system", "content": SYSTEM_PROMPT}]
        for user, reply in self.history[-self.history_len:]:
            messages += [{"role": "user", "content": user}, {"role": "assistant", "content": reply}]
        messages.append({"role": "user", "content": prompt})
        try:
            for turn in range(self.max_turns):
                res.turns = turn + 1
                start = time.perf_counter()
                reply = await asyncio.to_thread(self.llm.chat, messages, self.llm_tools)
                res.llm_times.append(time.perf_counter() - start)
                if not reply.tool_calls:
                    res.text = reply.content.strip() or "I could not produce an answer."
                    break
                messages.append(reply.as_message())
                valid: list[Valid | None] = []
                errors: dict[int, str] = {}
                for i, call in enumerate(reply.tool_calls):
                    try:
                        valid.append(self._validate(call))
                    except ValueError as err:
                        valid.append(None)
                        errors[i] = str(err)
                if errors:
                    res.retries += 1
                    res.invalid.append({"turn": turn + 1, "errors": list(errors.values()),
                                        "calls": [(c.name, c.arguments) for c in reply.tool_calls]})
                    for i, call in enumerate(reply.tool_calls):
                        text = (f"INVALID: {errors[i]}. Fix it and call the tool again." if i in errors
                                else "Not run, because another call in this turn was invalid. Send all calls again.")
                        messages.append({"role": "tool", "content": text, "tool_name": call.name})
                    if res.retries > self.max_retries:
                        res.failed = True
                        res.text = "Sorry, I could not turn that into a valid rule. Please rephrase."
                        break
                    continue
                results = {}
                if await self._execute(reply.tool_calls, valid, results, res, ctx, t0, prompt) == "end":
                    break
                for i, call in enumerate(reply.tool_calls):
                    messages.append({"role": "tool", "content": results.get(i, "done"), "tool_name": call.name})
            else:
                res.capped = True
                res.text = f"Stopped after {self.max_turns} turns; please narrow the request."
        finally:
            res.t_total = time.perf_counter() - t0
        self.history.append((prompt, res.text))
        return res

    async def _execute(self, calls, valid, results, res, ctx, t0, prompt) -> str:
        for v in valid:
            res.model_calls.append(v.norm)
        for i, v in enumerate(valid):
            if v.name in READ_TOOLS:
                results[i] = await self._run_read(v, res, ctx, t0)
        writes = [(i, v) for i, v in enumerate(valid) if v.name in WRITE_TOOLS]
        if not writes:
            return "continue"
        return await self._run_writes(writes, results, res, ctx, t0, prompt)

    async def _run_read(self, v: Valid, res: Result, ctx: Ctx, t0: float) -> str:
        try:
            if v.name == "list_firewall_rules":
                rules = await self._list(res, t0, v.obj)
                ctx.listed = True
                res.table = format_rules(rules)
                return self._compact(v.obj, rules)
            if v.name == "get_firewall_status":
                return json.dumps(json.loads(await self._call(res, t0, v.name, {})))
            data = json.loads(await self._call(res, t0, v.name, {"name": v.obj}))
            return f"{data['service']} is port {data['port']}/{data['protocol']}"
        except RuntimeError as err:
            return f"ERROR: {err}"

    def _refuse(self, res: Result, prompt: str, reason: str, commands: list[str]) -> str:
        res.refused = reason
        res.text = f"{reason}. Nothing was changed."
        backend.audit(prompt=prompt, decision="refused", reason=reason, commands=commands)
        return "end"

    async def _run_writes(self, writes, results, res, ctx, t0, prompt) -> str:
        undos = [(i, v) for i, v in writes if v.name == "undo_last_change"]
        adds = [(i, v) for i, v in writes if v.name == "add_firewall_rule"]
        dels = [(i, v) for i, v in writes if v.name == "delete_firewall_rule"]
        if undos:
            return await self._run_undo(res, t0, prompt, results, [i for i, _ in writes])
        # delete one rule at a time: rule numbers shift after every deletion
        if len(dels) + ctx.deletes > 1:
            return self._refuse(res, prompt, "blocked: only one rule can be deleted per request, because rule numbers "
                                              "shift after each deletion", [])
        if dels and not ctx.listed:
            rules = await self._list(res, t0, dels[0][1].obj.chain)
            ctx.listed = True
            for i, _ in writes:
                results[i] = ("NOT RUN: the rules have not been read in this request. " + self._compact(dels[0][1].obj.chain, rules)
                              + " Check the rule number and call delete_firewall_rule again.")
            return "continue"

        planned = []
        for _, v in sorted(dels, key=lambda x: -x[1].obj.rule_number):
            planned.append({"kind": "delete", "obj": v.obj, "pos": 0,
                            "argv": ["iptables", "-D", v.obj.chain, str(v.obj.rule_number)]})
        ordered = sorted(adds, key=lambda x: x[1].obj.action != "ACCEPT")     # specific ACCEPTs before broad DROPs
        for pos, (_, v) in enumerate(ordered, start=1):
            planned.append({"kind": "add", "obj": v.obj, "pos": pos, "argv": build_argv(v.obj, pos)})
        commands = [shlex.join(p["argv"]) for p in planned]

        for p in planned:
            try:
                check_rule(p["obj"], p["argv"]) if p["kind"] == "add" else check_argv(p["argv"])
            except LockoutError as err:
                if not (self.override and await asyncio.to_thread(self.override, str(err))):
                    return self._refuse(res, prompt, str(err), commands)
            except GuardrailError as err:
                return self._refuse(res, prompt, str(err), commands)

        high = any(p["kind"] == "add" and is_high_risk(p["obj"]) for p in planned)
        res.confirm_requests.append(commands)
        start = time.perf_counter()
        approved = await asyncio.to_thread(self.confirm, f"{len(planned)} change(s) will be made:", commands, high)
        res.confirm_wait += time.perf_counter() - start
        if not approved:
            res.declined = True
            res.text = "Cancelled; nothing changed."
            backend.audit(prompt=prompt, decision="declined", commands=commands)
            return "end"

        chain = next((p["obj"].chain if p["kind"] == "delete" else ("INPUT" if p["obj"].direction == "in" else "OUTPUT"))
                     for p in planned)
        before = await self._list(res, t0, chain)
        done = 0
        try:
            for p in planned:
                if p["kind"] == "add":
                    r = p["obj"]
                    await self._call(res, t0, "add_firewall_rule", {
                        "protocol": r.protocol, "source": r.source, "action": r.action, "port": r.port,
                        "direction": r.direction, "position": p["pos"], "comment": r.comment})
                else:
                    await self._call(res, t0, "delete_firewall_rule",
                                     {"chain": p["obj"].chain, "rule_number": p["obj"].rule_number})
                done += 1
        except RuntimeError as err:
            for _ in range(done):                      # undo what this request already applied
                await self._call(res, t0, "undo_last_change", {})
            res.rolled_back = True
            res.failed = True
            res.text = f"Failed: {err}. All changes from this request were rolled back."
            backend.audit(prompt=prompt, decision="approved", result=f"rolled back: {err}", commands=commands)
            return "end"
        ctx.deletes += len(dels)
        self.last_batch = done
        res.changed = True
        after = await self._list(res, t0, chain)
        marks = set(range(1, len(ordered) + 1))
        res.table = "Before:\n" + format_rules(before) + "\n\nAfter:\n" + format_rules(after, marks)
        backend.audit(prompt=prompt, decision="approved", result="applied", commands=commands)
        for (i, _), cmd in zip(sorted(writes), [shlex.join(p["argv"]) for p in planned] + [""] * len(writes)):
            results[i] = f"Applied: {cmd}"
        return "continue"

    async def _run_undo(self, res, t0, prompt, results, indexes) -> str:
        n = max(1, self.last_batch)
        commands = [f"iptables-restore  # the rule set saved before the last request ({n} snapshot(s))"]
        res.confirm_requests.append(commands)
        start = time.perf_counter()
        approved = await asyncio.to_thread(self.confirm, "The last change will be undone:", commands, False)
        res.confirm_wait += time.perf_counter() - start
        if not approved:
            res.declined = True
            res.text = "Cancelled; nothing changed."
            backend.audit(prompt=prompt, decision="declined", commands=commands)
            return "end"
        try:
            for _ in range(n):
                await self._call(res, t0, "undo_last_change", {})
        except RuntimeError as err:
            res.failed = True
            res.text = f"Could not undo: {err}."
            return "end"
        self.last_batch = 0
        res.changed = True
        res.table = format_rules(await self._list(res, t0, "INPUT"))
        backend.audit(prompt=prompt, decision="approved", result="undone", commands=commands)
        for i in indexes:
            results[i] = "Undone: the previous rule set was restored."
        return "continue"

    # -- slash commands (no LLM) -----------------------------------------------------------------
    async def slash(self, line: str) -> str:
        res = Result(prompt=line)
        t0 = time.perf_counter()
        if line == "/rules":
            return format_rules(await self._list(res, t0))
        if line == "/status":
            return json.dumps(json.loads(await self._call(res, t0, "get_firewall_status", {})), indent=2)
        if line == "/undo":
            await self._run_undo(res, t0, line, {}, [])
            return res.output() or "Done."
        return "Commands: /rules  /status  /undo  /help  /exit. Anything else is sent to the assistant."
