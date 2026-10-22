"""backend.py - the iptables adapter: snapshot, execute, verify, roll back, audit."""
import json
import os
import subprocess
import time

from guardrails import check_argv, check_rule
from rules import DeleteRequest, RuleRequest, build_argv, parse_rule

HOME = os.environ.get("FW_HOME") or os.path.expanduser("~/.agent18")


def audit(**entry) -> None:
    os.makedirs(HOME, exist_ok=True)
    with open(os.path.join(HOME, "audit.jsonl"), "a") as log:
        log.write(json.dumps({"time": round(time.time(), 3), **entry}) + "\n")


class IptablesBackend:
    def __init__(self) -> None:
        self.snapshots: list[str] = []      # saved iptables-save output, newest last
        self._inserts = 0                   # for the FW_TEST_FAIL_INSERT test hook

    # -- low level ---------------------------------------------------------------------------
    def run(self, argv: list[str], stdin: str | None = None) -> str:
        fail_at = os.environ.get("FW_TEST_FAIL_INSERT")          # test hook: fail the Nth insert
        if fail_at and argv[0] == "iptables" and "-I" in argv:
            self._inserts += 1
            if self._inserts == int(fail_at):
                raise RuntimeError("injected failure (test hook)")
        cmd = argv if os.environ.get("FW_NO_SUDO") else ["sudo", "-n", *argv]
        try:
            proc = subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=10, shell=False)
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"{argv[0]} timed out after 10 s")
        if proc.returncode != 0:
            msg = proc.stderr.strip() or f"{argv[0]} exited with code {proc.returncode}"
            if "password is required" in msg or "not allowed" in msg:
                msg = "permission denied: check the agent18 sudoers entry"
            audit(command=" ".join(argv), exit_code=proc.returncode, error=msg)
            raise RuntimeError(msg)
        audit(command=" ".join(argv), exit_code=0)
        return proc.stdout

    def _snapshot(self) -> str:
        snap = self.run(["iptables-save"])
        self.snapshots.append(snap)
        os.makedirs(HOME, exist_ok=True)
        with open(os.path.join(HOME, f"snap-{int(time.time() * 1000)}.rules"), "w") as fh:
            fh.write(snap)
        return snap

    def _rollback(self, snap: str) -> None:
        self.run(["iptables-restore"], stdin=snap)
        self.snapshots.pop()

    # -- read tools --------------------------------------------------------------------------
    def rules(self, chain: str = "INPUT") -> list[dict]:
        lines = [l for l in self.run(["iptables", "-S", chain]).splitlines() if l.startswith("-A")]
        return [parse_rule(line, n) for n, line in enumerate(lines, start=1)]

    def status(self) -> dict:
        policies = {}
        for line in self.run(["iptables", "-S"]).splitlines():
            if line.startswith("-P"):
                _, chain, policy = line.split()
                policies[chain] = policy
        return {
            "backend": self.run(["iptables", "-V"]).strip(),
            "policies": policies,
            "rules": {c: len(self.rules(c)) for c in ("INPUT", "OUTPUT")},
        }

    # -- write tools -------------------------------------------------------------------------
    def add(self, rule: RuleRequest, position: int = 1) -> dict:
        argv = build_argv(rule, position)
        check_rule(rule, argv, lockout=False)       # the client owns the lockout override
        snap = self._snapshot()
        try:
            self.run(argv)
            self.run(["iptables", "-C", argv[2], *argv[4:]])    # verify the rule exists
        except RuntimeError:
            self._rollback(snap)
            raise
        return {"applied": " ".join(argv)}

    def delete(self, req: DeleteRequest) -> dict:
        argv = ["iptables", "-D", req.chain, str(req.rule_number)]
        check_argv(argv)
        before = len(self.rules(req.chain))
        if req.rule_number > before:
            raise RuntimeError(f"rule {req.rule_number} does not exist; {req.chain} has {before} rule(s)")
        snap = self._snapshot()
        try:
            self.run(argv)
            if len(self.rules(req.chain)) != before - 1:
                raise RuntimeError("the rule count did not drop by one")
        except RuntimeError:
            self._rollback(snap)
            raise
        return {"deleted": " ".join(argv)}

    def undo(self) -> dict:
        if not self.snapshots:
            raise RuntimeError("there is no snapshot to restore")
        snap = self.snapshots.pop()
        self.run(["iptables-restore"], stdin=snap)
        return {"restored": "the rule set from before the last change"}
