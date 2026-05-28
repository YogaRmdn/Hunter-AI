from utils.helpers import run_command, which
from typing import List


class Scanner:
    def __init__(self, targets: List[str]):
        self.targets = targets
        self.results = {"open_ports": [], "services": {}, "nuclei": []}
        self.nuclei_results = []

    def run_all(self) -> dict:
        self._fast_scan()
        self._service_detect()
        return self.results

    def _fast_scan(self):
        if which("masscan"):
            target_str = " ".join(self.targets)
            r = run_command([
                "masscan", target_str,
                "--ports", "1-10000",
                "--rate", "1000",
                "-oJ", "/tmp/hunter_masscan.json",
            ], timeout=120)
            if r["success"]:
                try:
                    import json
                    with open("/tmp/hunter_masscan.json") as f:
                        data = json.load(f)
                    for entry in data:
                        self.results["open_ports"].append({
                            "ip": entry.get("ip"),
                            "port": entry.get("ports", [{}])[0].get("port"),
                            "protocol": entry.get("ports", [{}])[0].get("proto"),
                        })
                except Exception:
                    pass
        elif which("nmap"):
            target_str = " ".join(self.targets[:5])
            r = run_command([
                "nmap", "-T4", "--top-ports", "1000",
                "-oG", "-", target_str,
            ], timeout=300)
            if r["success"]:
                for line in r["stdout"].splitlines():
                    if "/open/" in line:
                        parts = line.split()
                        for part in parts:
                            m = __import__("re").match(r"(\d+)/open/(\w+)", part)
                            if m:
                                self.results["open_ports"].append({
                                    "port": int(m.group(1)),
                                    "protocol": m.group(2),
                                })

    def _service_detect(self):
        if not self.results["open_ports"]:
            return
        if which("nmap"):
            unique_ips = list(set(p.get("ip", self.targets[0]) for p in self.results["open_ports"]))[:3]
            ports = ",".join(str(p["port"]) for p in self.results["open_ports"][:50])
            if ports:
                r = run_command([
                    "nmap", "-sV", "-p", ports,
                    "-oG", "-", " ".join(unique_ips),
                ], timeout=300)
                if r["success"]:
                    for line in r["stdout"].splitlines():
                        if "/open/" in line:
                            parts = line.strip().split("\t")
                            for p in parts:
                                m = __import__("re").match(r"(\d+)/open/(\w+)/{0,1}(.*)", p)
                                if m:
                                    port = int(m.group(1))
                                    svc = m.group(3).strip() if m.group(3) else "unknown"
                                    self.results["services"][port] = svc

    def run_nuclei(self, target: str):
        if which("nuclei"):
            r = run_command([
                "nuclei", "-u", f"https://{target}",
                "-silent", "-o", "/tmp/hunter_nuclei.txt",
                "-json", "-rl", "50",
            ], timeout=300)
            if r["success"]:
                for line in r["stdout"].splitlines():
                    try:
                        import json
                        self.nuclei_results.append(json.loads(line))
                    except Exception:
                        self.nuclei_results.append({"raw": line})
            else:
                r2 = run_command([
                    "nuclei", "-u", f"http://{target}",
                    "-silent", "-o", "/tmp/hunter_nuclei.txt",
                    "-json", "-rl", "50",
                ], timeout=300)
                if r2["success"]:
                    for line in r2["stdout"].splitlines():
                        try:
                            self.nuclei_results.append(json.loads(line))
                        except Exception:
                            self.nuclei_results.append({"raw": line})
