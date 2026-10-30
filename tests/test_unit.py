"""Unit tests: schema, command building, guardrails, parsing and rollback logic. No kernel access needed."""
import os
import sys

import pytest
from pydantic import ValidationError

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent import parse_inline_calls  # noqa: E402
from backend import IptablesBackend  # noqa: E402
from guardrails import GuardrailError, LockoutError, check_argv, check_rule, is_high_risk  # noqa: E402
from rules import DeleteRequest, RuleRequest, build_argv, format_rules, parse_rule  # noqa: E402


def rule(**kw):
    base = dict(protocol="tcp", source="10.0.0.9", action="DROP")
    base.update(kw)
    return RuleRequest(**base)


# -- schema validation ---------------------------------------------------------------------------
def test_source_is_normalised_to_a_network():
    assert rule().source == "10.0.0.9/32"


def test_anywhere_becomes_the_default_route():
    assert rule(source="anywhere").source == "0.0.0.0/0"


def test_case_and_synonyms_are_normalised():
    r = rule(protocol="TCP", action="drop", direction="Incoming")
    assert (r.protocol, r.action, r.direction) == ("tcp", "DROP", "in")


@pytest.mark.parametrize("bad", [
    dict(port=99999),                          # port out of range
    dict(port=0),
    dict(protocol="icmp", port=22),            # a port needs tcp or udp
    dict(source="not-an-ip"),
    dict(source="10.0.0.5/24"),                # host bits set
    dict(source="::1"),                        # IPv6 is out of scope
    dict(action="ALLOWISH"),
    dict(protocol="gre"),
    dict(comment="x; rm -rf /"),               # metacharacters in the free-text field
])
def test_schema_rejects_bad_arguments(bad):
    with pytest.raises(ValidationError):
        rule(**bad)


def test_delete_request_needs_a_positive_number():
    with pytest.raises(ValidationError):
        DeleteRequest(chain="INPUT", rule_number=0)
    assert DeleteRequest(chain="input", rule_number=3).chain == "INPUT"


# -- command building ----------------------------------------------------------------------------
def test_example_prompt_builds_the_documented_commands():
    ssh = rule(protocol="tcp", port=22, source="192.168.1.50", action="ACCEPT", comment="allow ssh")
    block = rule(protocol="all", source="192.168.1.50", action="DROP", comment="block host")
    assert " ".join(build_argv(ssh, 1)) == (
        "iptables -I INPUT 1 -s 192.168.1.50/32 -p tcp --dport 22 -m comment --comment agent18: allow ssh -j ACCEPT")
    assert " ".join(build_argv(block, 2)) == (
        "iptables -I INPUT 2 -s 192.168.1.50/32 -m comment --comment agent18: block host -j DROP")


def test_outgoing_rules_use_output_chain_and_destination():
    argv = build_argv(rule(direction="out"), 1)
    assert argv[2:6] == ["OUTPUT", "1", "-d", "10.0.0.9/32"]


# -- guardrails ----------------------------------------------------------------------------------
@pytest.mark.parametrize("text", [
    "iptables -F", "iptables --flush INPUT", "iptables -X", "iptables --delete-chain",
    "iptables -P INPUT DROP", "iptables -P FORWARD REJECT",
    "iptables -I INPUT 1 -i lo -j DROP", "rm -rf /", "mkfs.ext4 /dev/sda", "dd if=/dev/zero of=/dev/sda",
    ":(){ :|:& };:",
])
def test_blacklist_refuses_destructive_text(text):
    with pytest.raises(GuardrailError):
        check_argv(text.split())


@pytest.mark.parametrize("arg", ["a;b", "a&b", "a|b", "a`b", "a$b", "a<b", "a>b"])
def test_metacharacters_are_refused(arg):
    with pytest.raises(GuardrailError):
        check_argv(["iptables", "-I", "INPUT", arg])


def test_clean_command_passes():
    check_argv(["iptables", "-I", "INPUT", "1", "-s", "10.0.0.9/32", "-j", "DROP"])


def test_loopback_drop_is_refused_but_accept_is_allowed():
    r = rule(source="127.0.0.1")
    with pytest.raises(GuardrailError):
        check_rule(r, build_argv(r, 1))
    ok = rule(source="127.0.0.1", action="ACCEPT")
    check_rule(ok, build_argv(ok, 1))


def test_drop_everything_from_everywhere_is_refused():
    r = rule(protocol="all", source="0.0.0.0/0")
    with pytest.raises(GuardrailError):
        check_rule(r, build_argv(r, 1))


def test_drop_of_one_port_from_anywhere_is_allowed():
    r = rule(port=25, source="0.0.0.0/0")
    check_rule(r, build_argv(r, 1))


def test_lockout_protection(monkeypatch):
    monkeypatch.setenv("SSH_CONNECTION", "10.0.0.5 51000 10.0.0.1 22")
    mine = rule(protocol="all", source="10.0.0.5")
    with pytest.raises(LockoutError):
        check_rule(mine, build_argv(mine, 1))
    net = rule(protocol="all", source="10.0.0.0/24")
    with pytest.raises(LockoutError):
        check_rule(net, build_argv(net, 1))
    ssh_port = rule(protocol="tcp", port=22, source="0.0.0.0/0")
    with pytest.raises(LockoutError):
        check_rule(ssh_port, build_argv(ssh_port, 1))
    other = rule(source="10.0.0.9")                       # someone else
    check_rule(other, build_argv(other, 1))
    web = rule(port=80, source="10.0.0.5")                # my IP, but not my SSH port
    check_rule(web, build_argv(web, 1))
    accept = rule(source="10.0.0.5", action="ACCEPT")
    check_rule(accept, build_argv(accept, 1))


def test_no_lockout_check_outside_ssh(monkeypatch):
    monkeypatch.delenv("SSH_CONNECTION", raising=False)
    r = rule(protocol="all", source="10.0.0.5")
    check_rule(r, build_argv(r, 1))


def test_wide_blocks_are_high_risk():
    assert is_high_risk(rule(source="10.0.0.0/16"))
    assert not is_high_risk(rule(source="10.0.0.0/24"))
    assert not is_high_risk(rule(source="10.0.0.0/8", action="ACCEPT"))


# -- parsing and formatting ----------------------------------------------------------------------
def test_parse_rule_with_comment_and_port():
    line = '-A INPUT -s 192.168.1.50/32 -p tcp -m tcp --dport 22 -m comment --comment "agent18: allow ssh" -j ACCEPT'
    r = parse_rule(line, 1)
    assert (r["source"], r["protocol"], r["port"], r["action"], r["comment"]) == (
        "192.168.1.50/32", "tcp", 22, "ACCEPT", "agent18: allow ssh")


def test_parse_rule_without_source_means_anywhere():
    r = parse_rule("-A INPUT -p tcp -m tcp --dport 443 -j ACCEPT", 2)
    assert r["source"] == "0.0.0.0/0" and r["port"] == 443


def test_format_rules_stars_new_rows():
    rows = [parse_rule("-A INPUT -s 1.2.3.4/32 -j DROP", 1), parse_rule("-A INPUT -s 5.6.7.8/32 -j DROP", 2)]
    out = format_rules(rows, {1})
    assert "  1* DROP" in out and "  2  DROP" in out
    assert "(no rules)" in format_rules([])


def test_inline_json_calls_are_recovered():
    calls = parse_inline_calls('```json\n{"name": "list_firewall_rules", "parameters": {"chain": "INPUT"}}\n```')
    assert [(c.name, c.arguments) for c in calls] == [("list_firewall_rules", {"chain": "INPUT"})]
    assert parse_inline_calls("I can only manage firewall rules.") == []
    # a call written after a sentence of prose is recovered too; JSON that is not a call is ignored
    prose = 'Let me fix that.\n\n{"name": "delete_firewall_rule", "parameters": {"chain": "INPUT", "rule_number": 1}}'
    assert [(c.name, c.arguments) for c in parse_inline_calls(prose)] == [("delete_firewall_rule", {"chain": "INPUT", "rule_number": 1})]
    assert parse_inline_calls('The result is {"ok": true} and that is all.') == []
    assert parse_inline_calls('Broken {"name": "x", "parameters": {') == []


# -- rollback logic with a mocked command runner -------------------------------------------------
class FakeBackend(IptablesBackend):
    def __init__(self, fail_on=None):
        super().__init__()
        self.calls, self.fail_on = [], fail_on

    def run(self, argv, stdin=None):
        self.calls.append((argv, stdin))
        if self.fail_on and self.fail_on in argv:
            raise RuntimeError("boom")
        return "SNAPSHOT" if argv[0] == "iptables-save" else ""


def test_failed_verification_restores_the_snapshot(tmp_path, monkeypatch):
    monkeypatch.setattr("backend.HOME", str(tmp_path))
    fb = FakeBackend(fail_on="-C")
    with pytest.raises(RuntimeError):
        fb.add(rule(), 1)
    assert fb.calls[-1] == (["iptables-restore"], "SNAPSHOT")
    assert fb.snapshots == []


def test_undo_without_snapshot_is_an_error():
    with pytest.raises(RuntimeError):
        FakeBackend().undo()
