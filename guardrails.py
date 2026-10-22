"""guardrails.py - blacklist, shell-metacharacter and lockout checks (section 3.3)."""
import os
import re
from ipaddress import ip_address, ip_network

from rules import RuleRequest

BLACKLIST = [
    (re.compile(r"\s-(F|X)\b|--flush|--delete-chain"), "wipes rules or chains"),
    (re.compile(r"-P\s+(INPUT|OUTPUT|FORWARD)\s+(DROP|REJECT)"), "changes a default policy to deny"),
    (re.compile(r"-i\s+lo\b|\b127\.0\.0\.0/8\b"), "touches the loopback interface"),
    (re.compile(r"rm\s+-rf\s+/|mkfs|dd\s+if=|:\(\)\s*\{"), "destructive shell command"),
]
META = re.compile(r"[;&|`$<>]")
LOOPBACK = ip_network("127.0.0.0/8")


class GuardrailError(Exception):
    """The call is refused outright."""


class LockoutError(GuardrailError):
    """The rule would cut the administrator's own SSH session; only an explicit override clears it."""


def check_argv(argv: list[str]) -> None:
    text = " ".join(argv)
    for pattern, reason in BLACKLIST:
        if pattern.search(text):
            raise GuardrailError(f"blocked: {reason}")
    if any(META.search(arg) for arg in argv):
        raise GuardrailError("blocked: shell metacharacter in an argument")


def check_rule(rule: RuleRequest, argv: list[str], lockout: bool = True) -> None:
    check_argv(argv)
    net = ip_network(rule.source)
    if rule.action != "ACCEPT":
        if net.subnet_of(LOOPBACK):
            raise GuardrailError("blocked: the rule touches the loopback network (127.0.0.0/8)")
        if rule.port is None and net.prefixlen == 0:
            raise GuardrailError("blocked: would drop all traffic from everywhere")
    if lockout:
        check_lockout(rule)


def check_lockout(rule: RuleRequest) -> None:
    conn = os.environ.get("SSH_CONNECTION")   # "client_ip client_port server_ip server_port"
    if not conn or rule.action == "ACCEPT" or rule.direction != "in":
        return
    client_ip, _, _, server_port = conn.split()
    if rule.protocol in ("tcp", "all") and ip_address(client_ip) in ip_network(rule.source) \
            and rule.port in (None, int(server_port)):
        raise LockoutError(f"blocked: this rule would cut your own SSH session from {client_ip}")


def is_high_risk(rule: RuleRequest) -> bool:
    """Wide blocks (a /16 or larger) need the full word 'yes' instead of 'y'."""
    return rule.action != "ACCEPT" and ip_network(rule.source).prefixlen <= 16
