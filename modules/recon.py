import subprocess
import json
import re
import socket
from utils.helpers import run_command, which


class Recon:
    def __init__(self, target: str):
        self.target = target
        self.results = {"domains": [], "ips": [], "dns": {}, "whois": {}}

    def run_all(self) -> dict:
        self._subfinder()
        self._dns_enum()
        self._whois_lookup()
        return self.results

    def _subfinder(self):
        if which("subfinder"):
            r = run_command(["subfinder", "-d", self.target, "-silent"])
            if r["success"]:
                self.results["domains"] = [d.strip() for d in r["stdout"].splitlines() if d.strip()]
        else:
            self._subfinder_fallback()

    def _subfinder_fallback(self):
        try:
            import dns.resolver
            for sub in ["www", "mail", "admin", "api", "dev", "test", "staging", "blog", "cdn", "app"]:
                try:
                    answers = dns.resolver.resolve(f"{sub}.{self.target}", "A")
                    self.results["domains"].append(f"{sub}.{self.target}")
                    for a in answers:
                        self.results["ips"].append(str(a))
                except Exception:
                    pass
        except ImportError:
            pass

    def _dns_enum(self):
        try:
            import dns.resolver
            for qtype in ["A", "AAAA", "MX", "NS", "TXT", "SOA"]:
                try:
                    answers = dns.resolver.resolve(self.target, qtype)
                    self.results["dns"][qtype] = [str(r) for r in answers]
                except Exception:
                    self.results["dns"][qtype] = []
        except ImportError:
            try:
                r = run_command(["dig", self.target, "ANY", "+short"])
                if r["success"]:
                    self.results["dns"]["ANY"] = [l.strip() for l in r["stdout"].splitlines() if l.strip()]
            except Exception:
                pass

    def _whois_lookup(self):
        if which("whois"):
            r = run_command(["whois", self.target], timeout=30)
            if r["success"]:
                lines = r["stdout"].splitlines()
                for kw in ["Registrar:", "Creation Date:", "Registrant", "Name Server"]:
                    for line in lines:
                        if line.startswith(kw):
                            k = kw.lower().replace(" ", "_").replace(":", "")
                            self.results["whois"][k] = line.split(":", 1)[1].strip()
        else:
            try:
                import whois as whois_lib
                w = whois_lib.whois(self.target)
                self.results["whois"] = {k: str(v) for k, v in w.items() if v}
            except ImportError:
                self.results["whois"]["error"] = "whois not available"
