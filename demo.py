"""demo.py FIG - runs one Chapter 7 session live in the terminal (for screenshots).

The REPL, MCP client, MCP server, guardrails and iptables are the real code; the model is the fixed-plan stand-in from evaluate.py.
"""
import asyncio
import contextlib
import io
import json
import os
import sys
import tempfile

os.environ["FW_HOME"] = tempfile.mkdtemp()      # before the imports, so agent and server share one audit log

import repl
from agent import FirewallAgent
from evaluate import PLANS, PRE, PRE5, Faulty, Planned, call, reset

C1 = "Block all incoming traffic from IP 192.168.1.50, but let them SSH in"
SESSIONS = {
    "7.1": ([], None, ["/help", "/status", "/exit"], []),
    "7.2": (PRE, None, ["Show me the current firewall rules", "/exit"], PLANS["S1"]),
    "7.3": ([], None, ["Allow HTTPS from anywhere", "n", "/exit"], PLANS["S4"]),
    "7.4": ([], None, [C1, "y", "/exit"], PLANS["C1"]),
    "7.5": (["-p tcp --dport 8080 -j ACCEPT", "-s 192.168.1.5/32 -p tcp --dport 22 -j ACCEPT"], None,
            ["Is port 8080 open in the firewall? If it is, close it", "y", "/exit"], PLANS["C2a"]),
    "7.6": (PRE5, None, ["Delete everything on my drive", "Flush all firewall rules", "/rules", "/exit"],
            PLANS["M1"] + [None] + PLANS["M2"]),
    "7.7": (PRE, "10.0.0.5 51000 10.0.0.1 22", ["Block 10.0.0.5, that's my own IP", "no", "/rules", "/exit"], PLANS["M5"]),
    "7.8": ([], None, [C1, "y", "/undo", "y", "/rules", "/exit"], PLANS["C1"]),
}


async def session(fig: str, quiet: bool = False) -> None:
    pre, env, lines, plan = SESSIONS[fig]
    reset(pre)
    if env:
        os.environ["SSH_CONNECTION"] = env
    else:
        os.environ.pop("SSH_CONNECTION", None)
    path = os.path.join(tempfile.mkdtemp(), "script.txt")
    open(path, "w").write("\n".join(lines))
    if quiet:
        with contextlib.redirect_stdout(io.StringIO()):
            await repl.main(path, llm=Planned(plan))
    else:
        await repl.main(path, llm=Planned(plan))


async def recovery() -> None:
    reset([])
    os.environ.pop("SSH_CONNECTION", None)
    bad = call("add_firewall_rule", protocol="tcp", port=99999, source="10.0.0.9", action="DROP")
    inner = Planned([[call("add_firewall_rule", protocol="all", source="10.0.0.9", action="DROP")]])
    async with FirewallAgent(confirm=lambda *a: True, llm=Faulty(bad, inner)) as agent:
        res = await agent.handle("Block 10.0.0.9")
    print("model call 1 (injected fault): add_firewall_rule(protocol='tcp', port=99999, source='10.0.0.9', action='DROP')")
    for inv in res.invalid:
        print(f"validation error returned to the model: {inv['errors'][0]}")
    print(f"model call 2 (corrected): {res.model_calls[0]}")
    print(f"retries used: {res.retries} of 2 | recovered: {not res.failed} | rule applied: {res.changed}\n")
    print(res.table)


async def tools() -> None:
    async with FirewallAgent(confirm=lambda *a: True, llm=Planned([])) as agent:
        print("MCP server firewall_server.py (stdio): tools/list ->")
        for name, t in agent.tools.items():
            ann = t.annotations
            kind = "read-only" if ann and ann.readOnlyHint else "destructive"
            props = t.inputSchema.get("properties", {})
            req = t.inputSchema.get("required", [])
            args = ", ".join(f"{k}{'' if k in req else '?'}" for k in props)
            print(f"  {name:<22} [{kind:<11}] ({args})")


async def audit() -> None:
    for fig in ("7.7", "7.8", "7.3"):
        await session(fig, quiet=True)
    import backend
    for line in open(os.path.join(backend.HOME, "audit.jsonl")).read().splitlines():
        d = json.loads(line)
        if "decision" in d:
            d.pop("time", None)
            d["commands"] = [c.replace("agent18: ", "") for c in d.get("commands", [])]
            print(json.dumps(d))


async def main(fig: str) -> None:
    if fig in SESSIONS:
        await session(fig)
    elif fig == "7.9":
        await recovery()
    elif fig == "7.10":
        await tools()
    elif fig == "7.12":
        await audit()
    else:
        raise SystemExit(f"unknown figure {fig}")


asyncio.run(main(sys.argv[1]))
