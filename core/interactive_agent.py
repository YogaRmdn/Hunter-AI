from core.llm_client import LLMClient
from core.tool_registry import ToolRegistry
from utils.helpers import Spinner
from colorama import init, Fore, Style
import time

init(autoreset=True)

MAX_AUTO_ITERATIONS = 10


def border(text: str = "", color=Fore.CYAN):
    return f"{color}{'─' * 60}{Style.RESET_ALL}"


def section(title: str, color=Fore.MAGENTA):
    print(f"\n{color}{'─' * 60}{Style.RESET_ALL}")
    print(f"  {color}◆ {title}{Style.RESET_ALL}")
    print(f"{color}{'─' * 60}{Style.RESET_ALL}")


class InteractiveAgent:
    def __init__(self, llm_provider: str = "ollama", llm_model: str = "llama3", api_key: str = None):
        self.llm = LLMClient(provider=llm_provider, model=llm_model, api_key=api_key)
        self.registry = ToolRegistry()
        self.running = True
        self.conversation_count = 0

    def print_ai(self, msg: str):
        print(f"\n  {Fore.CYAN}◆{Style.RESET_ALL} {msg}")

    def print_tool_run(self, tool_name: str, params: dict):
        p_str = ", ".join(f"{k}={v}" for k, v in params.items()) if params else ""
        print(f"\n  {Fore.YELLOW}▶{Style.RESET_ALL} {Fore.GREEN}{tool_name}{Style.RESET_ALL} {Fore.WHITE}{p_str}{Style.RESET_ALL}")

    def print_tool_result(self, result: str):
        for line in result.split("\n"):
            if line.strip():
                print(f"    {Fore.WHITE}{line}{Style.RESET_ALL}")
            else:
                print()
        print()

    def print_error(self, msg: str):
        print(f"\n  {Fore.RED}◆ {msg}{Style.RESET_ALL}")

    def show_help(self):
        statuses = self.llm.router.get_status()
        active = [s["name"] for s in statuses if s["available"]]

        print(border("", Fore.MAGENTA))
        self.print_ai(f"""{Fore.GREEN}Halo! Aku Hunter-AI — asisten security testing kamu!{Style.RESET_ALL}

Aku paham bahasa apa pun, santai aja ngomongnya.

{Fore.YELLOW}🔗 Multi-LLM Chain:{Style.RESET_ALL} opencode → ollama → openai → claude → gemini → deepseek
{Fore.YELLOW}⚡ Active:{Style.RESET_ALL} {', '.join(active) if active else 'fallback parser (none connected)'}

{Fore.YELLOW}💡 Contoh perintah:{Style.RESET_ALL}
  {Fore.WHITE}• "scan ip 192.168.1.1"{Style.RESET_ALL}         → port scanning
  {Fore.WHITE}• "cari subdomain example.com"{Style.RESET_ALL}  → subdomain enum
  {Fore.WHITE}• "test example.com"{Style.RESET_ALL}            → auto workflow lengkap
  {Fore.WHITE}• "cek vuln https://site.com"{Style.RESET_ALL}   → nuclei vuln scan
  {Fore.WHITE}• "dir busting http://site.com"{Style.RESET_ALL} → gobuster
  {Fore.WHITE}• "cari exploit apache"{Style.RESET_ALL}         → searchsploit
  {Fore.WHITE}• "teknologi website example.com"{Style.RESET_ALL} → whatweb
  {Fore.WHITE}• "cari flag di foto.jpg"{Style.RESET_ALL}        → stego + strings + exiftool
  {Fore.WHITE}• "buat laporan"{Style.RESET_ALL}                → generate report
  {Fore.WHITE}• "status / hasil"{Style.RESET_ALL}              → lihat progress
  {Fore.WHITE}• "reset"{Style.RESET_ALL}                       → mulai dari awal

{Fore.YELLOW}Pake bahasa apa aja boleh! Aku paham kok 😎{Style.RESET_ALL}
        """.strip())
        print(border("", Fore.MAGENTA))

    def process_ai_decision(self, user_input: str, iteration: int = 0, is_continuation: bool = False):
        with Spinner("AI memproses perintah..."):
            decision = self.llm.decide(user_input, self.registry.context)

        response = decision.get("response", "")
        tools = decision.get("tools", [])
        ask_user = decision.get("ask_user")

        tools = [t for t in tools if t.get("name")]

        if response:
            if is_continuation:
                label = f"Step {iteration}" if iteration > 1 else "Analisis"
                print(f"  {Fore.CYAN}◆ {label}:{Style.RESET_ALL} {response}")
            else:
                self.print_ai(response)
            if not tools:
                if is_continuation:
                    section("Selesai", Fore.GREEN)
                return

        if not response and not tools and not ask_user:
            if is_continuation:
                return
            self.print_ai("Hmm, aku kurang paham maksudnya. Coba ketik `help` buat lihat contoh atau tanya langsung!")
            return

        if ask_user:
            print(f"\n  {Fore.YELLOW}◆ {ask_user}{Style.RESET_ALL}")
            return

        if not tools:
            return

        results = []
        terminal_tools = {"stego_analyze", "file_read", "show_context", "ai_analyze", "generate_report"}
        for tool_cmd in tools:
            name = tool_cmd.get("name", "")
            params = tool_cmd.get("params", {})

            self.print_tool_run(name, params)
            spinner_msg = f"Menjalankan {name}..."
            with Spinner(spinner_msg):
                result = self.registry.run_tool(name, params)
            self.print_tool_result(result)
            results.append({"tool": name, "result": result})

        all_terminal = all(r["tool"] in terminal_tools for r in results)
        if results and not all_terminal and iteration < MAX_AUTO_ITERATIONS:
            continuation = "=== HASIL TOOLS ===\n"
            for r in results:
                truncated = r["result"][:1500] if len(r["result"]) > 1500 else r["result"]
                continuation += f"\n--- {r['tool']} ---\n{truncated}\n"
            continuation += "\n=== LANJUTKAN ===\nBerdasarkan hasil di atas, apa langkah selanjutnya? Panggil tool lagi kalo masih perlu. Kalo udah selesai, beri response dan jangan panggil tool."
            self.process_ai_decision(continuation, iteration + 1, is_continuation=True)

    def run(self):
        statuses = self.llm.router.get_status()
        active = next((s for s in statuses if s["available"]), None)

        section("Hunter-AI v3.0 — Multi-LLM Security Agent", Fore.CYAN)
        print(f"  {Fore.WHITE}  'Kamu suruh, AI jalankan, Tools merundung'{Style.RESET_ALL}")

        chain_parts = []
        for s in statuses:
            if s["available"]:
                chain_parts.append(f"{Fore.GREEN}● {s['name']}{Style.RESET_ALL}")
            else:
                chain_parts.append(f"{Fore.RED}○ {s['name']}{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}🔗 Chain:{Style.RESET_ALL} {' → '.join(chain_parts)}")

        if active:
            print(f"  {Fore.WHITE}⚡ Active:{Style.RESET_ALL} {Fore.GREEN}{active['label']}{Style.RESET_ALL}")
            self.print_ai(f"Halo! Aku siap bantu testing, bug bounty, atau CTF kamu!")
        else:
            print(f"  {Fore.WHITE}💡 Setup:{Style.RESET_ALL} export {Fore.GREEN}OPENCODE_API_KEY{Style.RESET_ALL}, {Fore.GREEN}ANTHROPIC_API_KEY{Style.RESET_ALL}, {Fore.GREEN}OPENAI_API_KEY{Style.RESET_ALL}, {Fore.GREEN}GEMINI_API_KEY{Style.RESET_ALL}, atau {Fore.GREEN}DEEPSEEK_API_KEY{Style.RESET_ALL}")
            print(f"  {Fore.WHITE}   Atau:{Style.RESET_ALL} install & jalankan {Fore.GREEN}ollama serve{Style.RESET_ALL}")
            self.print_ai(f"Halo! Pake fallback parser dulu ya. Set API key biar lebih cerdas!")
        self.print_ai(f"Ketik {Fore.YELLOW}help{Style.RESET_ALL} buat lihat contoh atau langsung tanya aja!")
        print(f"{Fore.MAGENTA}{'─' * 60}{Style.RESET_ALL}")

        while self.running:
            try:
                user_input = input(f"\n{Fore.MAGENTA}🎯 Kamu>{Style.RESET_ALL} ").strip()
                if not user_input:
                    continue

                self.conversation_count += 1

                if user_input.lower() in ("exit", "quit", "keluar", "q", "exit()"):
                    self.print_ai(f"Sampai jumpa! Semoga dapat {Fore.GREEN}banyak bounty{Style.RESET_ALL} dan {Fore.YELLOW}flag{Style.RESET_ALL}! 🔥")
                    self.running = False
                    continue

                if user_input.lower() in ("help", "bantuan", "?", "halo", "hai", "hallo", "helo", "testing"):
                    self.show_help()
                    continue

                if user_input.lower() in ("reset", "clear", "reset context"):
                    self.registry = ToolRegistry()
                    self.llm.router.history = []
                    self.print_ai("✅ Context direset! Mulai dari awal yuk!")
                    continue

                self.process_ai_decision(user_input)

            except KeyboardInterrupt:
                print()
                self.print_ai("Dadah! 👋")
                self.running = False
            except EOFError:
                print()
                self.running = False
            except Exception as e:
                self.print_error(f"Error: {e}")
