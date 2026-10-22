# Agent 18 (Smart Firewall): setup and run guide

Group 18: Soham Patil (24BCI0275), Jakeer Harsha (24BCE2668).
Soham's repository: https://github.com/sohampatil99/smart-firewall-agent-group18
Jakeer's repository: https://github.com/harshazakir/Operating-systems

The agent changes real `iptables` rules, so everything below runs inside a Docker container. The container has its own
network namespace, so a wrong rule cannot affect your computer, and every rule disappears when the container exits.

## 1. What you need

- **Docker Desktop** (Windows 10/11 with WSL2, macOS, or Docker Engine on Linux). Start it and wait until it says "running".
- About 3 GB of free disk space and an internet connection for the first build.
- Optional: Python 3 on your computer, only to run `summarize.py` on the results.
- Optional, for a live model: Ollama (the design model) or a small GGUF model file (what we used). Not needed for the tests.

Commands below are for **Windows PowerShell**. On macOS or Linux, replace `${PWD}\results` with `$PWD/results`.

## 2. Get the code

Unzip the archive and open a terminal in the `code` folder, or clone it:

```powershell
git clone https://github.com/sohampatil99/smart-firewall-agent-group18.git
cd smart-firewall-agent-group18
```

## 3. Build the two images (about 5 minutes the first time)

```powershell
docker build -t agent18-test .
docker build -f Dockerfile.demo -t agent18-demo .
```

`agent18-test` is Ubuntu 24.04 with Python, `iptables`, the MCP SDK (pinned below version 2) and a normal user `fw`.
`sudo` is limited to `iptables`, `iptables-save` and `iptables-restore`. `agent18-demo` adds the code on top.

## 4. Run the automated tests (no model needed)

```powershell
docker run --rm --cap-add=NET_ADMIN agent18-demo pytest -p no:cacheprovider tests
```

Expected last line: `60 passed` (46 unit tests and 14 integration tests against the real MCP server and real `iptables`).
`--cap-add=NET_ADMIN` is required; without it `iptables` fails with a permission error.

## 5. Try the REPL (no model needed)

```powershell
docker run --rm -it --cap-add=NET_ADMIN -e FW_STUB_LLM=1 agent18-demo python repl.py
```

`FW_STUB_LLM=1` swaps in a stub that just echoes your sentence. Slash commands work for real:
`/status`, `/rules`, `/undo`, `/help`, `/exit`.

## 6. Reproduce the Chapter 7 screenshots

Each figure is one command (the model is the fixed-plan stand-in, so the output is the same every time):

```powershell
docker run --rm --cap-add=NET_ADMIN agent18-demo python demo.py 7.4
```

Use `7.1` to `7.10` and `7.12` for `demo.py`. Figure 7.11 is the test run from section 4.
Examples: `7.4` is the chained request (ACCEPT then DROP), `7.6` the destructive prompts, `7.7` lockout protection, `7.8` undo.

## 7. Re-run the evaluation (Chapter 5)

### 7a. Fixed plans (no model, about 2 minutes)

```powershell
docker run --rm --cap-add=NET_ADMIN -v "${PWD}\results:/results" agent18-demo python evaluate.py --mode oracle --runs 3 --out /results/oracle.json
python summarize.py results\oracle.json
```

Expected headline numbers: intent accuracy 9/9, safety 8/8, error recovery 12/12, rollback 6/6.

### 7b. Live model, option 1: a small GGUF file (what we measured)

1. Download `qwen2.5-0.5b-instruct-q4_k_m.gguf` (469 MB) from the Hugging Face repo `Qwen/Qwen2.5-0.5B-Instruct-GGUF` into a `models` folder next to this file.
2. Run (about 10 minutes on a CPU):

```powershell
docker run --rm --cap-add=NET_ADMIN -v "${PWD}\models:/app/models:ro" -v "${PWD}\results:/results" agent18-demo python evaluate.py --mode live --model /app/models/qwen2.5-0.5b-instruct-q4_k_m.gguf --runs 1 --out /results/live.json
python summarize.py results\live.json
```

Our run gave 2/9 intent accuracy, 8/8 safety, 0/4 error recovery. A model this small is not expected to do well.

### 7c. Live model, option 2: Ollama and Llama 3.1 8B (the design model; we did not run this)

1. Install Ollama on your computer, then `ollama pull llama3.1:8b`.
2. Make Ollama reachable from containers: set the environment variable `OLLAMA_HOST=0.0.0.0` before starting `ollama serve`.
3. Run the REPL or the evaluation with `OLLAMA_HOST` pointing at your computer:

```powershell
docker run --rm -it --cap-add=NET_ADMIN -e OLLAMA_HOST=http://host.docker.internal:11434 agent18-demo python repl.py
docker run --rm --cap-add=NET_ADMIN -e OLLAMA_HOST=http://host.docker.internal:11434 -v "${PWD}\results:/results" agent18-demo python evaluate.py --mode live --model llama3.1:8b --runs 1 --out /results/live-llama.json
```

On Linux add `--add-host=host.docker.internal:host-gateway`. In the REPL, type a sentence such as
`Block all incoming traffic from IP 192.168.1.50, but let them SSH in`, read the preview, and answer `y` or `n`.

## 8. Running without Docker (Linux only, use a virtual machine)

This changes the machine's real firewall. Only do it on a throwaway VM.

```bash
pip install -r requirements.txt
echo 'YOUR_USER ALL=(root) NOPASSWD: /usr/sbin/iptables, /usr/sbin/iptables-save, /usr/sbin/iptables-restore' | sudo tee /etc/sudoers.d/agent18
FW_STUB_LLM=1 python repl.py          # or: OLLAMA_HOST=http://localhost:11434 python repl.py
```

Run as root instead with `FW_NO_SUDO=1`. Audit log and snapshots go to `~/.agent18` (set `FW_HOME` to change it).

## 9. What is where

| Path | Purpose |
| --- | --- |
| `rules.py`, `guardrails.py`, `backend.py` | Schema and command building, safety checks, iptables adapter with snapshot and rollback |
| `firewall_server.py` | MCP server with the six tools |
| `agent.py`, `repl.py` | MCP client and LLM loop, the REPL |
| `tests/` | Unit and integration tests |
| `evaluate.py`, `summarize.py` | Evaluation harness and result summary |
| `demo.py`, `capture.py`, `screenshots/` | Chapter 7 demos, captures and the real screenshots |
| `results/` | Measured results (`oracle.json`, `live-0.5b.json`), test log, captured transcripts |

## 10. Troubleshooting

- **"Cannot connect to the Docker daemon" / "failed to connect to the docker API"**: Docker Desktop is not running. Start it and retry.
- **`iptables: Permission denied` or `you must be root`**: the container was started without `--cap-add=NET_ADMIN`.
- **`No module named 'mcp.server.fastmcp'`**: the MCP SDK 2.x was installed. This project needs version 1.x; the Dockerfile pins `mcp[cli]>=1.9,<2`.
- **The build is slow or stalls**: the first build downloads about 1 GB. A slow connection only makes it take longer; rerun and Docker resumes from its cache.
- **A live run is very slow**: a model on CPU takes about 15 seconds per request. Use fewer runs (`--runs 1`).
- **The `-v` path fails on Windows**: run the command from inside the project folder so `${PWD}` is correct, and keep the quotes.
- **Rules disappeared after a run**: expected. They live only inside the container.
