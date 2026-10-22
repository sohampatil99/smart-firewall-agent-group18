"""Integration tests: real MCP server over stdio, real iptables. Run inside the Docker test container."""
import asyncio
import os
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent import FirewallAgent, LLMReply, ToolCall  # noqa: E402
from rules import parse_rule  # noqa: E402

pytestmark = pytest.mark.skipif(shutil.which("iptables") is None, reason="needs iptables and sudo")


def sh(*argv):
    return subprocess.run(["sudo", "-n", *argv], capture_output=True, text=True, check=True).stdout


def chain():
    out = [l for l in sh("iptables", "-S", "INPUT").splitlines() if l.startswith("-A")]
    return [(r["action"], r["protocol"], r["port"], r["source"]) for r in (parse_rule(l, i) for i, l in enumerate(out, 1))]


@pytest.fixture(autouse=True)
def clean(tmp_path, monkeypatch):
    sh("iptables", "-F")
    monkeypatch.setenv("FW_HOME", str(tmp_path))
    monkeypatch.delenv("SSH_CONNECTION", raising=False)
    monkeypatch.delenv("FW_TEST_FAIL_INSERT", raising=False)
    yield
    sh("iptables", "-F")


class Scripted:
    """An LLM that replays fixed replies, then answers 'ok'."""
    def __init__(self, *replies):
        self.replies = list(replies)

    def chat(self, messages, tools):
        return self.replies.pop(0) if self.replies else LLMReply("ok", [])


def call(name, **args):
    return ToolCall(name, args)


def reply(*calls):
    return LLMReply("", list(calls))


def run(llm, prompts, answers=("y",), override=None):
    asked = []
    answers = list(answers)

    def confirm(summary, commands, high):
        asked.append(commands)
        return (answers.pop(0) if answers else "n") == "y"

    async def go():
        async with FirewallAgent(confirm=confirm, override=override, llm=llm) as agent:
            return [await agent.handle(p) for p in prompts], agent

    results, agent = asyncio.run(go())
    return results, asked


SSH = call("add_firewall_rule", protocol="tcp", port=22, source="192.168.1.50", action="ACCEPT", direction="in")
DROP = call("add_firewall_rule", protocol="all", source="192.168.1.50", action="DROP", direction="in")


def test_server_exposes_the_six_tools():
    async def go():
        async with FirewallAgent(confirm=lambda *a: True, llm=Scripted()) as agent:
            return agent.tools

    tools = asyncio.run(go())
    assert set(tools) == {"get_firewall_status", "list_firewall_rules", "lookup_service_port",
                          "add_firewall_rule", "delete_firewall_rule", "undo_last_change"}
    assert tools["list_firewall_rules"].annotations.readOnlyHint is True
    assert tools["add_firewall_rule"].annotations.destructiveHint is True


def test_example_prompt_puts_accept_before_drop_with_one_confirmation():
    (res,), asked = run(Scripted(reply(DROP, SSH)), ["block 192.168.1.50 but let them ssh in"])
    assert chain() == [("ACCEPT", "tcp", 22, "192.168.1.50/32"), ("DROP", "all", None, "192.168.1.50/32")]
    assert len(asked) == 1 and len(asked[0]) == 2
    assert res.changed and "Before:" in res.table and "After:" in res.table


def test_declined_confirmation_changes_nothing():
    (res,), _ = run(Scripted(reply(SSH)), ["allow ssh from 192.168.1.50"], answers=("n",))
    assert chain() == [] and res.declined


def test_read_only_calls_need_no_confirmation():
    (res,), asked = run(Scripted(reply(call("list_firewall_rules"))), ["show rules"])
    assert asked == [] and "no rules" in res.table


def test_lockout_is_refused(monkeypatch):
    monkeypatch.setenv("SSH_CONNECTION", "10.0.0.5 51000 10.0.0.1 22")
    block_me = call("add_firewall_rule", protocol="all", source="10.0.0.5", action="DROP")
    (res,), asked = run(Scripted(reply(block_me)), ["block 10.0.0.5"], override=lambda reason: False)
    assert chain() == [] and asked == [] and "SSH session" in res.refused


def test_lockout_can_be_overridden_explicitly(monkeypatch):
    monkeypatch.setenv("SSH_CONNECTION", "10.0.0.5 51000 10.0.0.1 22")
    block_me = call("add_firewall_rule", protocol="all", source="10.0.0.5", action="DROP")
    (res,), _ = run(Scripted(reply(block_me)), ["block 10.0.0.5"], override=lambda reason: True)
    assert len(chain()) == 1 and res.changed


def test_blacklisted_target_is_refused():
    loop = call("add_firewall_rule", protocol="all", source="127.0.0.1", action="DROP")
    (res,), asked = run(Scripted(reply(loop)), ["block localhost"])
    assert chain() == [] and asked == [] and res.refused


def test_failed_second_insert_rolls_the_first_back(monkeypatch):
    monkeypatch.setenv("FW_TEST_FAIL_INSERT", "2")
    (res,), _ = run(Scripted(reply(DROP, SSH)), ["block and allow ssh"])
    assert chain() == [] and res.rolled_back


def test_undo_reverses_the_whole_last_request():
    results, _ = run(Scripted(reply(DROP, SSH), LLMReply("done", []), reply(call("undo_last_change")), LLMReply("undone", [])),
                     ["block but allow ssh", "undo that"], answers=("y", "y"))
    assert chain() == [] and results[1].changed


def test_delete_needs_the_rules_to_be_read_first():
    sh("iptables", "-I", "INPUT", "1", "-p", "tcp", "--dport", "8080", "-j", "ACCEPT")
    delete = call("delete_firewall_rule", chain="INPUT", rule_number=1)
    (res,), asked = run(Scripted(reply(delete), reply(delete)), ["close 8080"])
    assert chain() == [] and len(asked) == 1 and res.changed          # first delete was bounced, second ran


def test_only_one_deletion_per_request():
    for n in range(3):
        sh("iptables", "-I", "INPUT", "1", "-s", f"10.0.0.{n + 1}/32", "-j", "DROP")
    d1, d2 = (call("delete_firewall_rule", chain="INPUT", rule_number=n) for n in (1, 2))
    (res,), asked = run(Scripted(reply(call("list_firewall_rules")), reply(d1, d2)), ["delete every rule"])
    assert len(chain()) == 3 and asked == [] and "one rule" in res.refused


def test_invalid_call_is_returned_to_the_model_and_corrected():
    bad = call("add_firewall_rule", protocol="icmp", port=22, source="10.0.0.9", action="DROP")
    good = call("add_firewall_rule", protocol="all", source="10.0.0.9", action="DROP")
    (res,), _ = run(Scripted(reply(bad), reply(good)), ["block 10.0.0.9"])
    assert res.retries == 1 and res.changed and len(chain()) == 1


def test_three_invalid_outputs_give_up_cleanly():
    bad = call("block_ip", ip="10.0.0.9")
    (res,), _ = run(Scripted(*[reply(bad)] * 5), ["block 10.0.0.9"])
    assert res.failed and chain() == [] and "rephrase" in res.text


def test_turn_cap_stops_a_loop():
    (res,), _ = run(Scripted(*[reply(call("get_firewall_status"))] * 9), ["status forever"])
    assert res.capped and res.turns == 5
