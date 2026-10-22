"""rules.py - the one schema shared by the prompt, the client and the server."""
import shlex
from ipaddress import ip_network
from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

ANYWHERE = {"any", "anywhere", "everywhere", "*"}


class RuleRequest(BaseModel):
    protocol: Literal["tcp", "udp", "icmp", "all"]
    source: str
    action: Literal["ACCEPT", "DROP", "REJECT"]
    port: Optional[int] = Field(default=None, ge=1, le=65535)
    direction: Literal["in", "out"] = "in"
    comment: str = Field(default="", pattern=r"^[A-Za-z0-9 _.-]{0,64}$")

    @field_validator("protocol", mode="before")
    @classmethod
    def _protocol(cls, value):
        return value.strip().lower() if isinstance(value, str) else value

    @field_validator("action", mode="before")
    @classmethod
    def _action(cls, value):
        return value.strip().upper() if isinstance(value, str) else value

    @field_validator("direction", mode="before")
    @classmethod
    def _direction(cls, value):
        if isinstance(value, str):
            value = value.strip().lower()
            return {"incoming": "in", "inbound": "in", "outgoing": "out", "outbound": "out"}.get(value, value)
        return value

    @field_validator("port", mode="before")
    @classmethod
    def _port(cls, value):
        if isinstance(value, str) and value.strip().lower() in {"", "none", "null", "any", "all"}:
            return None
        return value

    @field_validator("source", mode="before")
    @classmethod
    def _source(cls, value):
        if isinstance(value, str) and value.strip().lower() in ANYWHERE:
            return "0.0.0.0/0"
        return value.strip() if isinstance(value, str) else value

    @field_validator("source")
    @classmethod
    def valid_network(cls, value: str) -> str:
        net = ip_network(value, strict=True)          # "192.168.1.50" -> "192.168.1.50/32"
        if net.version != 4:
            raise ValueError("only IPv4 is supported")
        return str(net)

    @model_validator(mode="after")
    def port_needs_tcp_or_udp(self):
        if self.port is not None and self.protocol not in ("tcp", "udp"):
            raise ValueError("a port needs protocol tcp or udp")
        return self


class DeleteRequest(BaseModel):
    chain: Literal["INPUT", "OUTPUT"] = "INPUT"
    rule_number: int = Field(ge=1)

    @field_validator("chain", mode="before")
    @classmethod
    def _chain(cls, value):
        return value.strip().upper() if isinstance(value, str) else value


def build_argv(rule: RuleRequest, position: int) -> list[str]:
    """Shell-free command building: the LLM never writes a command string."""
    chain, addr = ("INPUT", "-s") if rule.direction == "in" else ("OUTPUT", "-d")
    argv = ["iptables", "-I", chain, str(position), addr, rule.source]
    if rule.protocol != "all":
        argv += ["-p", rule.protocol]
    if rule.port is not None:
        argv += ["--dport", str(rule.port)]
    if rule.comment:
        argv += ["-m", "comment", "--comment", f"agent18: {rule.comment}"]
    return argv + ["-j", rule.action]


def parse_rule(line: str, number: int) -> dict:
    """Parse one `iptables -S` line such as '-A INPUT -s 1.2.3.4/32 -p tcp -m tcp --dport 22 -j DROP'."""
    tokens = shlex.split(line)
    opts: dict[str, str] = {}
    i = 0
    while i < len(tokens):
        if tokens[i].startswith("-") and i + 1 < len(tokens) and not tokens[i + 1].startswith("-"):
            opts.setdefault(tokens[i], tokens[i + 1])
            i += 2
        else:
            i += 1
    port = opts.get("--dport")
    return {
        "number": number,
        "chain": opts.get("-A"),
        "source": opts.get("-s", "0.0.0.0/0"),
        "destination": opts.get("-d", "0.0.0.0/0"),
        "protocol": opts.get("-p", "all"),
        "port": int(port) if port and port.isdigit() else port,
        "action": opts.get("-j"),
        "comment": opts.get("--comment", ""),
    }


def format_rules(rules: list[dict], new: frozenset | set = frozenset()) -> str:
    """Before-and-after table; new rows are starred."""
    header = f"{'#':>3}  {'ACTION':<7} {'PROTO':<5} {'PORT':<6} {'SOURCE':<18} COMMENT"
    if not rules:
        return header + "\n    (no rules)"
    rows = [
        f"{r['number']:>3}{'*' if r['number'] in new else ' '} {r['action']:<7} "
        f"{r['protocol']:<5} {r['port'] or 'any':<6} {r['source']:<18} {r['comment']}"
        for r in rules
    ]
    return "\n".join([header, *rows])
