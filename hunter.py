#!/usr/bin/env python3
import sys
import os
from colorama import Fore as f, Style as s

r = f.RED
b = f.BLUE
g = f.GREEN
y = f.YELLOW
bl = s.BRIGHT
rs = s.RESET_ALL

# Auto-detect & activate venv kalo dijalankan pake system python
_venv_python = os.path.join(os.path.dirname(__file__), ".venv", "bin", "python3")
if not sys.executable.startswith(os.path.join(os.path.dirname(__file__), ".venv")) and os.path.isfile(_venv_python):
    os.execv(_venv_python, [_venv_python] + sys.argv)

# Sekarang pasti pake venv Python
import argparse

BANNER = f"""{r}{bl}
██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗        █████╗ ██╗
██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗      ██╔══██╗██║
███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝█████╗███████║██║
██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗╚════╝██╔══██║██║
██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║      ██║  ██║██║
╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝      ╚═╝  ╚═╝╚═╝
{rs}"""


def main():
    print(BANNER)
    parser = argparse.ArgumentParser(
        description="Hunter-AI: Interactive AI Security Agent — Natural Language → Tool Execution",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                           # Auto: opencode → ollama → openai → claude → gemini → deepseek
  python main.py --llm openai              # Paksa pake OpenAI
  python main.py --llm claude --api-key sk-ant-xxx
        """,
    )
    parser.add_argument("--llm", choices=["opencode", "ollama", "openai", "claude", "gemini", "deepseek"], default="opencode", help="LLM provider (default: opencode = auto chain)")
    parser.add_argument("--model", default="", help="LLM model name")
    parser.add_argument("--api-key", help="API key untuk provider tertentu")

    args = parser.parse_args()

    from core.interactive_agent import InteractiveAgent
    agent = InteractiveAgent(
        llm_provider=args.llm,
        llm_model=args.model,
        api_key=args.api_key,
    )

    try:
        agent.run()
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
