"""repl.py - the interface layer: a read-eval-print loop for Agent 18.

python repl.py                  interactive
python repl.py --script FILE    replay the lines of FILE as if typed (used for the screenshots)
FW_STUB_LLM=1 python repl.py    echo the input instead of calling a model (Step 1 test)
"""
import asyncio
import os
import sys

from agent import FirewallAgent, OllamaLLM, StubLLM


async def main(script: str | None = None, llm=None) -> None:
    lines = iter(open(script, encoding="utf-8").read().splitlines()) if script else None

    def read(prompt: str) -> str:
        if lines is None:
            return input(prompt)
        try:
            line = next(lines)
        except StopIteration:
            raise EOFError
        print(prompt + line)
        return line

    def confirm(summary: str, commands: list, high_risk: bool) -> bool:
        print(summary)
        for cmd in commands:
            print("   ", cmd)
        word = "yes" if high_risk else "y"
        answer = read(f"Apply these changes? [{word}/N] ").strip().lower()
        return answer == word or (not high_risk and answer == "yes")

    def override(reason: str) -> bool:
        print(reason)
        return read("Type OVERRIDE to continue anyway: ").strip() == "OVERRIDE"

    llm = llm or (StubLLM() if os.environ.get("FW_STUB_LLM") else OllamaLLM())
    async with FirewallAgent(confirm=confirm, override=override, llm=llm) as agent:
        print("Agent 18: Smart Firewall. Type /help or /exit.")
        while True:
            try:
                line = (await asyncio.to_thread(read, "fw> ")).strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not line:
                continue
            if line in ("/exit", "/quit"):
                break
            if line.startswith("/"):
                print(await agent.slash(line))
            else:
                print((await agent.handle(line)).output())


if __name__ == "__main__":
    asyncio.run(main(sys.argv[2] if len(sys.argv) > 2 and sys.argv[1] == "--script" else None))
