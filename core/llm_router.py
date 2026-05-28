import os
import json
import re
from typing import Optional

# Load .env sebelum apa pun
from core.env_loader import load_env
load_env()


SYSTEM_PROMPT = """Kamu adalah **Hunter-AI**, asisten AI untuk **cybersecurity, bug bounty, dan CTF**.

## ATURAN UTAMA
- Jawab LANGSUNG ke poin, no basa-basi
- Kalo user nyebut file SPESIFIK — langsung pake tool yang tepat di file itu, JANGAN cari-cari di tempat lain
- Kalo user minta "cari flag di file.jpg" — langsung panggil `stego_analyze(path="file.jpg")` dan SELESAI
- Kalo user minta "cari flag" tanpa file — tanya file mana
- JANGAN pernah pake `file_list` atau `file_search` kalo user udah ngasih file tertentu
- JANGAN njelajah direktori sendiri tanpa disuruh
- SATU langkah selesai, langsung lapor. Gak perlu lanjut-lanjut kalo udah dapet jawaban.

## TOOLS
- subdomain_enum(domain) — cari subdomain
- dns_enum(target) — enum DNS records
- whois_lookup(target) — info domain
- nmap_scan(target, ports?) — port scanning
- masscan_scan(target, ports?, rate?) — fast scanning
- service_detect(target, ports?) — deteksi service
- nuclei_scan(target, severity?) — vulnerability scan
- gobuster_dir(url, wordlist?) — directory brute-force
- ffuf_fuzz(url, wordlist?) — web fuzzing
- whatweb_detect(target) — deteksi teknologi web
- tech_stack(target) — tech stack website
- searchsploit_lookup(search) — cari exploit
- ai_analyze(data) — analisis hasil
- generate_report(format?) — buat laporan
- show_context() — lihat progress
- auto_workflow(target) — auto testing lengkap
- file_read(path) — baca isi file
- file_list(path) — list direktori (HANYA kalo disuruh user)
- file_search(pattern, path?) — cari file berdasarkan NAMA di direktori
- stego_analyze(path) — analisa SATU file spesifik: strings + exiftool + steghide + binwalk + foremost

## FORMAT OUTPUT (WAJIB JSON)
{
  "tools": [{"name": "tool_name", "params": {"key": "value"}}],
  "response": "Pesan kamu ke user",
  "reasoning": "penjelasan"
}

Kalo cuma ngobrol:
{
  "tools": [],
  "response": "Jawaban kamu",
  "reasoning": "ngobrol"
}

INGAT: Jangan nambah-nambah langkah kalo gak perlu. Kalo user ngasih file tertentu, langsung analisa file itu dan lapor. STOP."
"""


PROVIDER_CONFIG = [
    {
        "name": "opencode",
        "label": "Opencode (Auto-Detect)",
        "env_key": None,
        "check_fn": "check_opencode",
        "query_fn": "query_opencode",
        "priority": 1,
    },
    {
        "name": "ollama",
        "label": "Ollama (Local)",
        "env_key": None,
        "check_fn": "check_ollama",
        "query_fn": "query_ollama",
        "priority": 2,
    },
    {
        "name": "openai",
        "label": "OpenAI GPT-4",
        "env_key": "OPENAI_API_KEY",
        "check_fn": "check_api_key",
        "query_fn": "query_openai",
        "priority": 3,
    },
    {
        "name": "claude",
        "label": "Anthropic Claude",
        "env_key": "ANTHROPIC_API_KEY",
        "check_fn": "check_api_key",
        "query_fn": "query_claude",
        "priority": 4,
    },
    {
        "name": "gemini",
        "label": "Google Gemini",
        "env_key": "GEMINI_API_KEY",
        "check_fn": "check_api_key",
        "query_fn": "query_gemini",
        "priority": 5,
    },
    {
        "name": "deepseek",
        "label": "DeepSeek",
        "env_key": "DEEPSEEK_API_KEY",
        "check_fn": "check_api_key",
        "query_fn": "query_deepseek",
        "priority": 6,
    },
]


def check_api_key(config: dict) -> bool:
    key = os.getenv(config["env_key"])
    return bool(key and key != "test")


def check_ollama(config: dict) -> bool:
    try:
        import requests
        r = requests.get("http://localhost:11434/api/tags", timeout=3)
        return r.status_code == 200
    except Exception:
        return False


def check_opencode(config: dict) -> bool:
    # OPENCODE_API_KEY = bisa pake opencode Zen API
    if os.getenv("OPENCODE_API_KEY"):
        return True
    # Ollama local
    try:
        import requests
        r = requests.get("http://localhost:11434/api/tags", timeout=3)
        if r.status_code == 200:
            return True
    except Exception:
        pass
    # Fallback: kalo ada ANTHROPIC atau OpenAI key, opencode bisa pake itu
    if os.getenv("ANTHROPIC_API_KEY") or os.getenv("OPENAI_API_KEY"):
        return True
    return False


def query_openai(config: dict, messages: list, model: str) -> str:
    from openai import OpenAI
    client = OpenAI(api_key=os.getenv(config["env_key"]))
    r = client.chat.completions.create(
        model=model or "gpt-4",
        messages=messages,
        temperature=0.4,
        max_tokens=4096,
    )
    return r.choices[0].message.content.strip()


def query_claude(config: dict, messages: list, model: str) -> str:
    import anthropic
    client = anthropic.Anthropic(api_key=os.getenv(config["env_key"]))
    system_msgs = [m for m in messages if m["role"] == "system"]
    other_msgs = [m for m in messages if m["role"] != "system"]
    system_prompt = system_msgs[0]["content"] if system_msgs else SYSTEM_PROMPT
    r = client.messages.create(
        model=model or "claude-3-5-sonnet-20241022",
        max_tokens=4096,
        system=system_prompt,
        messages=other_msgs,
        temperature=0.4,
    )
    return r.content[0].text.strip()


def query_gemini(config: dict, messages: list, model: str) -> str:
    import google.generativeai as genai
    genai.configure(api_key=os.getenv(config["env_key"]))
    gemini = genai.GenerativeModel(model or "gemini-2.0-flash")
    # Convert messages to Gemini format
    chat = gemini.start_chat()
    for m in messages:
        if m["role"] == "system":
            continue
        if m["role"] == "user":
            chat.send_message(m["content"])
    return chat.last.text.strip()


def query_deepseek(config: dict, messages: list, model: str) -> str:
    from openai import OpenAI
    client = OpenAI(
        api_key=os.getenv(config["env_key"]),
        base_url="https://api.deepseek.com/v1",
    )
    r = client.chat.completions.create(
        model=model or "deepseek-chat",
        messages=messages,
        temperature=0.3,
        max_tokens=4096,
    )
    return r.choices[0].message.content.strip()


def query_ollama(config: dict, messages: list, model: str) -> str:
    import requests
    r = requests.post(
        "http://localhost:11434/api/chat",
        json={
            "model": model or "llama3",
            "messages": messages,
            "stream": False,
            "options": {"temperature": 0.4, "num_predict": 4096},
        },
        timeout=180,
    )
    return r.json()["message"]["content"].strip()


def query_opencode(config: dict, messages: list, model: str) -> str:
    opencode_key = os.getenv("OPENCODE_API_KEY")
    if opencode_key:
        from openai import OpenAI
        client = OpenAI(
            api_key=opencode_key,
            base_url="https://opencode.ai/zen/v1",
        )
        r = client.chat.completions.create(
            model=model or os.getenv("OPENCODE_MODEL", "big-pickle"),
            messages=messages,
            temperature=0.4,
            max_tokens=4096,
        )
        return r.choices[0].message.content.strip()
    # Fallback: Ollama local
    try:
        return query_ollama(config, messages, model or "llama3")
    except Exception:
        pass
    # Fallback: Claude
    if os.getenv("ANTHROPIC_API_KEY"):
        c = {"env_key": "ANTHROPIC_API_KEY"}
        return query_claude(c, messages, model or "claude-3-5-sonnet-20241022")
    # Fallback: OpenAI
    if os.getenv("OPENAI_API_KEY"):
        c = {"env_key": "OPENAI_API_KEY"}
        return query_openai(c, messages, model or "gpt-4")
    raise ConnectionError("Tidak ada AI provider tersedia")


class LLMRouter:
    def __init__(self, preferred: str = "opencode", api_key: Optional[str] = None, model: str = ""):
        self.preferred = preferred
        self.model = model
        self.history = []
        self._active_provider = None
        self._active_config = None
        self._fallback_chain = []
        self._last_user_input = ""
        self._setup()

    def _setup(self):
        # Bangun fallback chain: preferred → sisanya urut priority
        all_providers = sorted(PROVIDER_CONFIG, key=lambda p: p["priority"])
        preferred_config = None
        others = []

        for p in all_providers:
            if p["name"] == self.preferred:
                preferred_config = p
            else:
                others.append(p)

        chain = []
        if preferred_config:
            chain.append(preferred_config)
        chain.extend(others)
        self._fallback_chain = chain

    def is_any_available(self) -> bool:
        return any(s["available"] for s in self.get_status())

    def get_status(self) -> list:
        statuses = []
        for p in self._fallback_chain:
            check_fn = globals().get(p["check_fn"])
            available = check_fn(p) if check_fn else False
            statuses.append({
                "name": p["name"],
                "label": p["label"],
                "available": available,
            })
        return statuses

    def _query_provider(self, provider_config: dict, messages: list) -> str:
        query_fn = globals().get(provider_config["query_fn"])
        if not query_fn:
            raise ValueError(f"Tidak ada query_fn untuk {provider_config['name']}")
        return query_fn(provider_config, messages, self.model)

    def add_message(self, role: str, content: str):
        self.history.append({"role": role, "content": content})
        if len(self.history) > 100:
            self.history = self.history[-100:]

    def query(self, prompt: str, fallback_input: str = "") -> str:
        self.add_message("user", prompt)
        messages = [{"role": "system", "content": SYSTEM_PROMPT}] + self.history

        for provider_config in self._fallback_chain:
            check_fn = globals().get(provider_config["check_fn"])
            if check_fn and not check_fn(provider_config):
                continue
            try:
                resp = self._query_provider(provider_config, messages)
                self._active_provider = provider_config["name"]
                self._active_config = provider_config
                self.add_message("assistant", resp)
                return resp
            except Exception:
                continue

        # Semua gagal → fallback ke parser
        from core.fallback_parser import parse
        fb = fallback_input or self._last_user_input or prompt
        r = parse(fb)
        self.add_message("assistant", json.dumps(r))
        return json.dumps(r)

    def decide(self, user_input: str, context: dict) -> dict:
        self._last_user_input = user_input

        if not self.is_any_available():
            from core.fallback_parser import parse
            fb_result = parse(user_input)
            if fb_result["tools"]:
                return fb_result
            return {
                "tools": [],
                "response": "⚠️ **Belum ada API key terdeteksi!**\n\n"
                            "Supaya aku jadi AI beneran, set salah satu API key:\n\n"
                            "```bash\n"
                            "export OPENAI_API_KEY=sk-xxx          # OpenAI GPT-4\n"
                            "export ANTHROPIC_API_KEY=sk-ant-xxx   # Claude\n"
                            "export GEMINI_API_KEY=xxx             # Gemini\n"
                            "export DEEPSEEK_API_KEY=sk-xxx        # DeepSeek\n"
                            "```\n"
                            "Atau jalanin Ollama di local:\n"
                            "```bash\n"
                            "ollama pull llama3 && ollama serve\n"
                            "```\n\n"
                            "Atu kalo mau pake opencode API: export OPENCODE_API_KEY=...",
                "reasoning": "no_api_key",
            }

        prompt = f"""=== PERINTAH USER ===
{user_input}

=== KONTEKS ===
{json.dumps(context, indent=2)}

Pilih tool yang sesuai.
Return ONLY JSON:"""

        raw = self.query(prompt, fallback_input=user_input)
        raw = raw.strip()
        raw = re.sub(r'^```(?:json)?\s*', '', raw)
        raw = re.sub(r'\s*```$', '', raw)

        try:
            result = json.loads(raw)
            if not isinstance(result, dict):
                raise ValueError
            result.setdefault("tools", [])
            result.setdefault("response", "")
            return result
        except (json.JSONDecodeError, ValueError):
            # Coba extract JSON dari text
            m = re.search(r'\{.*\}', raw, re.DOTALL)
            if m:
                try:
                    return json.loads(m.group())
                except json.JSONDecodeError:
                    pass
            # LLM returning raw text (conversation) — wrap it
            return {"tools": [], "response": raw[:2000], "reasoning": "conversation"}

    @property
    def active_provider(self) -> str:
        return self._active_provider or "fallback"
