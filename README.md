# Agent 18: Smart Firewall (prototype)

Natural-language firewall requests -> validated `iptables` rules, through an MCP server, with guardrails.

Group 18: Soham Patil (24BCI0275) and Jakeer Harsha (24BCE2668). Agentic Shell project, Agent 18 (Smart Firewall).
- Soham's repository: https://github.com/sohampatil99/smart-firewall-agent-group18
- Jakeer's repository: https://github.com/harshazakir/Operating-systems

Review 1, 2 and 3 reports are combined in one document (see the course submission).

Results in short (details in `results/` and Review 3, section 5.2): 60 automated tests pass; with fixed plans the pipeline scores
9/9 intent accuracy, 8/8 safety, 12/12 error recovery and 6/6 rollback; the small live model we used
(Qwen2.5-0.5B, not the Llama 3.1 8B named in the design) scores 2/9 intent accuracy. `screenshots/` holds real terminal captures.

**Final live run (Llama 3.1 8B):** the final live run uses Llama 3.1 8B through Ollama, the model named in the original project design
(`agent.py` uses it by default). Measured with the same harness as the 0.5B run, one run per prompt, on a laptop with an RTX 3050 (6 GB):

| Run | Intent accuracy | Safety | Error recovery | Rollback | Median LLM time per prompt |
| --- | --- | --- | --- | --- | --- |
| First run, `results/live-8b-before-fixes.json` | 6/9 | 8/8 | 3/4 (1/4 with the stricter check described below) | 2/2 | 2.6 s |
| After the fixes below, `results/live-8b.json` | 9/9 | 8/8 | 2/4 (4/4 with the original check) | 2/2 | 3.8 s |

The fixed-plan numbers above are unchanged by the fixes (re-run: 9/9, 8/8, 12/12, 6/6) and all 60 tests still pass.
Interactive REPL: `docker run --rm -it --cap-add=NET_ADMIN -e OLLAMA_HOST=http://host.docker.internal:11434 agent18-demo python repl.py`
(see section 7c of [SETUP_AND_RUN.md](SETUP_AND_RUN.md)).

**Setup and run instructions: [SETUP_AND_RUN.md](SETUP_AND_RUN.md)** (Docker Desktop is the only requirement).

| File | Role |
| --- | --- |
| `rules.py` | Pydantic schema, shell-free command building, `iptables -S` parser, table formatter |
| `guardrails.py` | Blacklist, metacharacter, loopback, all-traffic and SSH-lockout checks |
| `backend.py` | iptables adapter: snapshot, run, verify (`-C`), rollback, audit log |
| `firewall_server.py` | MCP server (FastMCP, stdio) exposing the six tools |
| `agent.py` | MCP client, LLM tool loop, validation and retries, confirmation, undo |
| `repl.py` | The REPL (`--script FILE` replays a session) |
| `evaluate.py`, `summarize.py` | Chapter 5 test plan and metrics |
| `capture.py` | Records the Chapter 7 terminal captures |
| `tests/` | 46 unit tests and 14 integration tests |
| `results/` | `oracle.json` (fixed plans), `live-0.5b.json` (Qwen2.5-0.5B), `live-8b-before-fixes.json` and `live-8b.json` (Llama 3.1 8B), logs, captures |

## Note on the submitted report, and what changed after the first 8B run

**Mismatch with the report.** The Llama 3.1 8B runs were made after the report was submitted. At submission this README
gave the 0.5B model's 2/9 as the live-model result, and the design model had not been run, so the 8B figures here, in `SETUP_AND_RUN.md` and
in `results/` go beyond what the submitted PDF contains. The code also changed after submission (listed below), so `agent.py`,
`firewall_server.py`, `evaluate.py` and `tests/test_unit.py` are newer than the code the report describes. The report was not changed. Its
fixed-plan and 0.5B numbers are the ones above and were re-checked against the new code.

**Why the first 8B run scored 6/9 intent accuracy and 3/4 error recovery, against 9/9 and 12/12 with fixed plans.** A fixed plan replays the
expected tool calls, so it tests the pipeline (validation, guardrails, rollback) with perfect model output. A live run tests the model, and
intent accuracy needs its tool calls to match the expected ones exactly. The first run missed three prompts:
- **"Block this IP but let them SSH in" (two tests).** The model added the SSH ACCEPT rule but blocked the IP with `protocol=tcp` instead of
  `all`, so only TCP traffic from that address was dropped.
- **"If port 8080 is open, close it".** The model wrote its next step as JSON text after a sentence of prose, naming `add_firewall_rule` (a DROP
  for port 8080) instead of `delete_firewall_rule`. The parser could not read it, so no call ran and the rule stayed open. After the parser and prompt
  fixes the model did call `delete_firewall_rule`, but with the argument `rule` instead of `rule_number`; the error ("rule_number: Field required")
  did not say what was wrong, so it repeated the call until the 5-turn limit. That needed a second fix (the parameter names in the feedback).
- **Error recovery:** after the made-up tool `block_ip`, the model's reply contained no usable tool call. The run record does not keep that reply.

**What was fixed**
- `parse_inline_calls` (`agent.py`) now also recovers a call written as JSON after a sentence of prose. Recovered calls go through the same
  validation, guardrails and confirmation as any other call.
- The system prompt says to use protocol `all` with no port to cover an address, to delete a rule (not add a DROP on top) to close a port, never to
  write a call as text, and, after an INVALID answer, to fix only that problem without inventing a port, protocol or address.
- The INVALID feedback now lists the tool's real parameter names and any unknown arguments the model sent. The `add_firewall_rule` and
  `delete_firewall_rule` descriptions in `firewall_server.py` say the same about ports and arguments.
- The error-recovery check in `evaluate.py` is stricter. It used to accept any DROP rule for 10.0.0.9; it now requires `DROP all` with no port,
  which is what "Block 10.0.0.9" asks for. That is why the first run drops from 3/4 to 1/4 and the fixed plans stay at 12/12.

**What is still wrong.** Error recovery is 2/4 with the stricter check. For "port out of range" the model ended with `DROP tcp 80` (a port it made
up) and for "port with icmp" with `DROP icmp`; both keep part of the injected bad call instead of falling back to "Block 10.0.0.9". Every one of the
four faults ended with some DROP rule for 10.0.0.9, so the original check scores it 4/4. I stopped changing the agent here because further fixes would
be written for this specific test.

**Caveats.** Each figure is one run per prompt, so it can move by a prompt or two between runs. The fixes were made after seeing the first
run's failures on these same tests, so the second run is not an independent test of the model; new prompts would be needed for that. Safety is 8/8
in every run because the guardrails sit outside the model. Latency went from 2.6 s to 3.8 s per prompt; the prompt is longer and there were more
retries, and the GPU/CPU split on this laptop adds noise.

## Reproduce (Docker Desktop, any host)

```powershell
docker build -t agent18-test .
$app = "$PWD"; $res = "$PWD\results"
# unit + integration tests
docker run --rm --cap-add=NET_ADMIN -v "${app}:/app:ro" -e PYTHONPATH=/app agent18-test pytest -p no:cacheprovider -v /app/tests
# fixed-plan evaluation (no model)
docker run --rm --cap-add=NET_ADMIN -v "${app}:/app:ro" -v "${res}:/results" -e PYTHONPATH=/app -w /app agent18-test python evaluate.py --mode oracle --runs 3 --out /results/oracle.json
# live model (put a GGUF file in .\models first; for Ollama use --model llama3.1:8b and set OLLAMA_HOST)
docker run --rm --cap-add=NET_ADMIN -v "${app}:/app:ro" -v "${res}:/results" -e PYTHONPATH=/app -w /app agent18-test python evaluate.py --mode live --model /app/models/qwen2.5-0.5b-instruct-q4_k_m.gguf --runs 1 --out /results/live.json
python summarize.py results\live.json
```

Use a test container only: the agent changes real firewall rules. Model files are not included.
