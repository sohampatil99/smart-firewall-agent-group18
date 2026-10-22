# Agent 18: Smart Firewall (prototype)

Natural-language firewall requests -> validated `iptables` rules, through an MCP server, with guardrails.

Group 18: Soham Patil (24BCI0275) and Jakeer Harsha (24BCE2668). Agentic Shell project, Agent 18 (Smart Firewall).
Review 1, 2 and 3 reports are combined in one document (see the course submission).

Results in short (details in `results/` and Review 3, section 5.2): 60 automated tests pass; with fixed plans the pipeline scores
9/9 intent accuracy, 8/8 safety, 12/12 error recovery and 6/6 rollback; the small live model that could be run in time
(Qwen2.5-0.5B, not the Llama 3.1 8B named in the design) scores 2/9 intent accuracy. `screenshots/` holds real terminal captures.

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
| `results/` | `oracle.json` (fixed plans), `live-0.5b.json` (Qwen2.5-0.5B), logs, captures |

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
