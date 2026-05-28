import os
import re


def find_env_file(start_dir: str = None) -> str:
    """Cari .env file dari direktori project ke atas."""
    if start_dir is None:
        start_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    current = os.path.abspath(start_dir)
    while True:
        env_path = os.path.join(current, ".env")
        if os.path.isfile(env_path):
            return env_path
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    return ""


def load_env(env_path: str = "") -> dict:
    """Load .env → os.environ. Return dict of keys loaded."""
    if not env_path:
        env_path = find_env_file()
    if not env_path:
        return {}

    loaded = {}
    try:
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Hapus prefix export kalo ada
                line = re.sub(r'^export\s+', '', line, count=1)
                m = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)=(.*)$', line)
                if not m:
                    continue
                key = m.group(1)
                value = m.group(2).strip()
                # Lepas kutip
                if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
                    value = value[1:-1]
                # env var eksisting lebih prioritas
                if key not in os.environ and value:
                    os.environ[key] = value
                    loaded[key] = value
    except Exception:
        pass
    return loaded


def get_api_keys() -> dict:
    """Return dict of detected API keys."""
    load_env()
    keys = {}
    mapping = {
        "OPENCODE_API_KEY": "opencode",
        "OPENAI_API_KEY": "openai",
        "ANTHROPIC_API_KEY": "claude",
        "GEMINI_API_KEY": "gemini",
        "DEEPSEEK_API_KEY": "deepseek",
    }
    for env_key, provider in mapping.items():
        val = os.getenv(env_key, "")
        if val:
            keys[provider] = val
    return keys
