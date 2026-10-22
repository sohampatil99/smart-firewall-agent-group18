"""firewall_server.py - MCP server exposing the six firewall tools over stdio."""
import json
import socket

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from backend import IptablesBackend
from rules import DeleteRequest, RuleRequest

mcp = FastMCP("agent18-firewall", log_level="WARNING")
backend = IptablesBackend()
READ = ToolAnnotations(readOnlyHint=True)
WRITE = ToolAnnotations(readOnlyHint=False, destructiveHint=True)


@mcp.tool(annotations=READ)
def get_firewall_status() -> str:
    """Report the iptables backend, each chain's default policy and how many rules INPUT and OUTPUT hold."""
    return json.dumps(backend.status())


@mcp.tool(annotations=READ)
def list_firewall_rules(chain: str = "INPUT") -> str:
    """Return the rules of one chain (INPUT or OUTPUT), in order, with their rule numbers."""
    return json.dumps({"chain": chain, "rules": backend.rules(DeleteRequest(rule_number=1, chain=chain).chain)})


@mcp.tool(annotations=READ)
def lookup_service_port(name: str) -> str:
    """Map a service name such as 'ssh', 'http' or 'https' to its TCP port."""
    try:
        return json.dumps({"service": name, "port": socket.getservbyname(name.strip().lower(), "tcp"), "protocol": "tcp"})
    except OSError:
        raise ValueError(f"unknown service {name!r}")


@mcp.tool(annotations=WRITE)
def add_firewall_rule(protocol: str, source: str, action: str, port: int | None = None,
                      direction: str = "in", position: int = 1, comment: str = "") -> str:
    """Insert one ACCEPT, DROP or REJECT rule. protocol is tcp, udp, icmp or all; source is an IPv4 address
    or network (use 0.0.0.0/0 for anywhere); direction is 'in' or 'out'. Called only after the guardrails approve it."""
    rule = RuleRequest(protocol=protocol, port=port, source=source, action=action,
                       direction=direction, comment=comment)
    return json.dumps(backend.add(rule, position))


@mcp.tool(annotations=WRITE)
def delete_firewall_rule(chain: str, rule_number: int) -> str:
    """Delete one rule from INPUT or OUTPUT by its rule number from list_firewall_rules."""
    return json.dumps(backend.delete(DeleteRequest(chain=chain, rule_number=rule_number)))


@mcp.tool(annotations=WRITE)
def undo_last_change() -> str:
    """Restore the rule set saved before the most recent change."""
    return json.dumps(backend.undo())


if __name__ == "__main__":
    mcp.run()   # stdio transport by default
