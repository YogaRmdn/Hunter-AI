import subprocess
import json
import shutil
import sys
import threading
import time
from pathlib import Path
from typing import List, Optional


class Spinner:
    def __init__(self, message: str = "", style: str = "dots"):
        self.message = message
        self.styles = {
            "dots": ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"],
            "line": ["─", "━", "═", "╌", "╍", "╎", "╏", "╎", "╍", "╌"],
            "arrow": ["▹▹▹", "▸▹▹", "▹▸▹", "▹▹▸"],
            "bounce": ["[    ]", "[=   ]", "[==  ]", "[=== ]", "[ ===]", "[  ==]", "[   =]", "[    ]"],
            "clock": ["🕐", "🕑", "🕒", "🕓", "🕔", "🕕", "🕖", "🕗", "🕘", "🕙", "🕚", "🕛"],
        }
        self.frames = self.styles.get(style, self.styles["dots"])
        self._running = False
        self._thread = None

    def _spin(self):
        while self._running:
            for frame in self.frames:
                if not self._running:
                    break
                sys.stdout.write(f"\r  {frame} {self.message}")
                sys.stdout.flush()
                time.sleep(0.1)
        sys.stdout.write("\r" + " " * (len(self.message) + 4) + "\r")
        sys.stdout.flush()

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=0.5)
        sys.stdout.write("\r" + " " * (len(self.message) + 4) + "\r")
        sys.stdout.flush()

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()


def run_command(cmd: List[str], timeout: int = 300) -> dict:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {
            "stdout": r.stdout,
            "stderr": r.stderr,
            "returncode": r.returncode,
            "success": r.returncode == 0,
        }
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": "TIMEOUT", "returncode": -1, "success": False}
    except FileNotFoundError:
        return {"stdout": "", "stderr": "COMMAND_NOT_FOUND", "returncode": -2, "success": False}


def which(tool: str) -> Optional[str]:
    return shutil.which(tool)


def ensure_tools(tools: List[str]) -> List[str]:
    missing = []
    for t in tools:
        if not which(t):
            missing.append(t)
    return missing


def save_json(path: str, data: dict):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
