from utils.helpers import run_command, which
from typing import List


class WebTools:
    def __init__(self, target: str, ports: List[dict]):
        self.target = target
        self.ports = ports
        self.results = {"directories": [], "params": [], "sqli": [], "tech_stack": []}

    def run_all(self) -> dict:
        self._tech_detect()
        self._dir_bruteforce()
        self._fuzz_params()
        return self.results

    def _tech_detect(self):
        if which("whatweb"):
            for p in self.ports:
                port = p.get("port", 80)
                proto = "https" if port in (443, 8443) else "http"
                r = run_command(["whatweb", f"{proto}://{self.target}:{port}", "--aggression", "1"], timeout=60)
                if r["success"]:
                    self.results["tech_stack"].append(r["stdout"].strip())

    def _dir_bruteforce(self):
        if which("gobuster"):
            for p in self.ports[:1]:
                port = p.get("port", 80)
                proto = "https" if port in (443, 8443) else "http"
                r = run_command([
                    "gobuster", "dir",
                    "-u", f"{proto}://{self.target}:{port}",
                    "-w", "/usr/share/wordlists/dirb/common.txt",
                    "-t", "30",
                    "-q",
                ], timeout=120)
                if r["success"]:
                    for line in r["stdout"].splitlines():
                        if line.strip():
                            self.results["directories"].append(line.strip())

    def _fuzz_params(self):
        if which("ffuf"):
            for p in self.ports[:1]:
                port = p.get("port", 80)
                proto = "https" if port in (443, 8443) else "http"
                r = run_command([
                    "ffuf", "-u", f"{proto}://{self.target}:{port}/FUZZ",
                    "-w", "/usr/share/wordlists/dirb/common.txt",
                    "-t", "30",
                    "-s",
                ], timeout=120)
                if r["success"] and r["stdout"].strip():
                    self.results["params"] = [l.strip() for l in r["stdout"].splitlines() if l.strip()]
