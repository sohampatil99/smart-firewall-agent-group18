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
(`agent.py` uses it by default). Measured with the same harness as the 0.5B run (one run per prompt, `results/live-8b.json`):
6/9 intent accuracy, 8/8 safety, 3/4 error recovery and 2/2 rollback, with a median of 2.6 s per prompt on a laptop with an RTX 3050 (6 GB).
The fixed-plan numbers above are unchanged. Interactive REPL: `docker run --rm -it --cap-add=NET_ADMIN -e OLLAMA_HOST=http://host.docker.internal:11434 agent18-demo python repl.py`
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
| `results/` | `oracle.json` (fixed plans), `live-0.5b.json` (Qwen2.5-0.5B), `live-8b.json` (Llama 3.1 8B), logs, captures |

## Note on the submitted report, and why the 8B numbers differ from the fixed-plan numbers

**Mismatch with the report.** The Llama 3.1 8B run was made on 30 October 2026, after the report was submitted. At submission this README
gave the 0.5B model's 2/9 as the live-model result, and the design model had not been run, so the 8B figures in this README, in
`SETUP_AND_RUN.md` and in `results/live-8b.json` go beyond what the submitted PDF contains. The report itself was not changed; the fixed-plan
and 0.5B numbers are exactly the ones it states.

**Why 6/9 intent accuracy and 3/4 error recovery, against 9/9 and 12/12 with fixed plans.** A fixed plan replays the expected tool calls, so
it tests the pipeline (validation, guardrails, rollback) with perfect model output. The live run tests the model, and intent accuracy needs
its tool calls to match the expected ones exactly. The three misses were:
- **C1 and C4 (the "block this IP but let them SSH in" request).** The model added the SSH ACCEPT rule correctly but blocked the IP with
  `protocol=tcp` instead of `all`, so only TCP traffic from that address is dropped, not all of it. The expected call uses `all`.
- **C2a ("if port 8080 is open, close it").** The model listed the rules, then wrote its next step as JSON text in its reply instead of making a
  tool call, and the JSON named `add_firewall_rule` (a DROP for port 8080) instead of `delete_firewall_rule`. No call ran, so the rule stayed open.

Error recovery injects one invalid tool call and checks that the model's next turn leads to a DROP rule for 10.0.0.9. With fixed plans that
turn is always correct. The 8B model missed one of the four faults:
- **Unknown tool name.** After the error for the made-up tool `block_ip`, the agent retried once but the model's reply contained no valid tool
  call, so no rule was added. The run record does not keep the reply text, so what it wrote instead is not recorded.
- **Caveat on the three recoveries.** The check only requires a DROP rule for 10.0.0.9. For "port out of range" and "port with icmp" the model
  repaired the call by inventing a port (`DROP tcp 80` and `DROP tcp 22`), which is narrower than "Block 10.0.0.9". Only "source not an IP"
  ended with `DROP all 10.0.0.9/32`.

Each figure comes from one run per prompt, so it can move by a prompt or two between runs. Safety is 8/8 in every run because the guardrails
sit outside the model.

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
