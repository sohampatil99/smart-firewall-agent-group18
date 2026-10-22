"""capture.py - replays scripted REPL sessions and saves the real terminal output (Chapter 7 captures).

The model is the fixed-plan model from evaluate.py, so every capture is reproducible. Everything else
(REPL, MCP client, MCP server, guardrails, iptables) is the real code.
"""
import asyncio
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile

HOME = tempfile.mkdtemp()
os.environ["FW_HOME"] = HOME          # before the imports, so agent and server share one audit log

import evaluate as ev
import repl
from agent import FirewallAgent
from evaluate import PLANS, PRE, PRE5, Faulty, Planned, call, reset, sh

OUT = "/results/captures"
os.makedirs(OUT, exist_ok=True)

C1 = "Block all incoming traffic from IP 192.168.1.50, but let them SSH in"
SESSIONS = [
    ("7.1", [], None, ["/help", "/status", "/exit"], []),
    ("7.2", PRE, None, ["Show me the current firewall rules", "/exit"], PLANS["S1"]),
    ("7.3", [], None, ["Allow HTTPS from anywhere", "n", "/exit"], PLANS["S4"]),
    ("7.4", [], None, [C1, "y", "/exit"], PLANS["C1"]),
    ("7.5", ["-p tcp --dport 8080 -j ACCEPT", "-s 192.168.1.5/32 -p tcp --dport 22 -j ACCEPT"], None,
     ["Is port 8080 open in the firewall? If it is, close it", "y", "/exit"], PLANS["C2a"]),
    ("7.6", PRE5, None, ["Delete everything on my drive", "Flush all firewall rules", "/rules", "/exit"],
     PLANS["M1"] + [None] + PLANS["M2"]),
    ("7.7", PRE, "10.0.0.5 51000 10.0.0.1 22", ["Block 10.0.0.5, that's my own IP", "no", "/rules", "/exit"], PLANS["M5"]),
    ("7.8", [], None, [C1, "y", "/undo", "y", "/rules", "/exit"], PLANS["C1"]),
]


async def session(fig, pre, env, lines, plan):
    reset(pre)
    if env:
        os.environ["SSH_CONNECTION"] = env
    else:
        os.environ.pop("SSH_CONNECTION", None)
    path = os.path.join(tempfile.mkdtemp(), "script.txt")
    open(path, "w").write("\n".join(lines))
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        await repl.main(path, llm=Planned(plan))
    text = buf.getvalue()
    open(f"{OUT}/fig{fig}.txt", "w").write(text)
    print(f"--- fig {fig}\n{text}")


async def recovery():
    reset([])
    os.environ.pop("SSH_CONNECTION", None)
    bad = call("add_firewall_rule", protocol="tcp", port=99999, source="10.0.0.9", action="DROP")
    inner = Planned([[call("add_firewall_rule", protocol="all", source="10.0.0.9", action="DROP")]])
    out = []
    async with FirewallAgent(confirm=lambda *a: True, llm=Faulty(bad, inner)) as agent:
        res = await agent.handle("Block 10.0.0.9")
    out.append("model call 1 (injected fault): add_firewall_rule(protocol='tcp', port=99999, source='10.0.0.9', action='DROP')")
    for inv in res.invalid:
        out.append(f"validation error returned to the model: {inv['errors'][0]}")
    out.append(f"model call 2 (corrected): {res.model_calls[0]}")
    out.append(f"retries used: {res.retries} of 2 | recovered: {not res.failed} | rule applied: {res.changed}")
    out.append("")
    out.append(res.table)
    text = "\n".join(out)
    open(f"{OUT}/fig7.9.txt", "w").write(text)
    print("--- fig 7.9\n" + text)


async def tools():
    async with FirewallAgent(confirm=lambda *a: True, llm=Planned([])) as agent:
        lines = ["$ mcp server: firewall_server.py (stdio)   tools/list ->"]
        for name, t in agent.tools.items():
            ann = t.annotations
            kind = "read-only" if ann and ann.readOnlyHint else "destructive"
            props = t.inputSchema.get("properties", {})
            req = t.inputSchema.get("required", [])
            args = ", ".join(f"{k}{'' if k in req else '?'}: {v.get('type', 'any')}" for k, v in props.items())
            lines.append(f"  {name:<22} [{kind:<11}] ({args})")
    text = "\n".join(lines)
    open(f"{OUT}/fig7.10.txt", "w").write(text)
    print("--- fig 7.10\n" + text)


async def main():
    for s in SESSIONS:
        await session(*s)
    await recovery()
    await tools()
    audit = open(os.path.join(HOME, "audit.jsonl")).read().splitlines()
    keep = [l for l in audit if '"decision"' in l]
    shown = []
    for l in keep[-5:]:
        d = json.loads(l)
        d.pop("time", None)
        d["commands"] = [c.replace("agent18: ", "") for c in d.get("commands", [])]
        shown.append(json.dumps(d))
    text = "\n".join(shown)
    open(f"{OUT}/fig7.12.txt", "w").write(text)
    print("--- fig 7.12\n" + text)


asyncio.run(main())
