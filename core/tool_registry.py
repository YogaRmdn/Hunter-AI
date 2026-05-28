import json
import os
import re
import time
from math import isqrt
from modules.recon import Recon
from modules.scanner import Scanner
from modules.web_tools import WebTools
from modules.exploit import Exploit
from utils.helpers import run_command, which


class ToolRegistry:
    def __init__(self):
        self.context = {
            "target": "",
            "targets": [],
            "recon": {"subdomains": [], "dns": {}, "whois": {}},
            "scan": {"open_ports": [], "services": {}, "nuclei": []},
            "web": {"directories": [], "tech_stack": [], "ffuf": []},
            "exploit": {"cve_matches": [], "searchsploit": []},
            "findings": [],
            "history": [],
            "last_target": "",
        }

    def update_context(self, key: str, value):
        self.context[key] = value

    def run_tool(self, tool_name: str, params: dict) -> str:
        handler = getattr(self, f"tool_{tool_name}", None)
        if handler:
            try:
                result = handler(**params)
                self.context["history"].append({
                    "tool": tool_name,
                    "params": params,
                    "timestamp": time.strftime("%H:%M:%S"),
                    "result_len": len(result) if result else 0,
                })
                return result
            except Exception as e:
                err = f"Error menjalankan {tool_name}: {e}"
                self.context["history"].append({"tool": tool_name, "params": params, "error": err})
                return err
        return f"Tool '{tool_name}' tidak dikenal"

    def run_tools(self, tools: list) -> list:
        results = []
        for tool_cmd in tools:
            name = tool_cmd.get("name", "")
            params = tool_cmd.get("params", {})
            r = self.run_tool(name, params)
            results.append({"tool": name, "params": params, "result": r})
        return results

    def tool_subdomain_enum(self, domain: str):
        rec = Recon(domain)
        rec._subfinder()
        subdomains = rec.results.get("domains", [])
        self.context["target"] = domain
        self.context["recon"]["subdomains"] = subdomains
        if subdomains:
            return f"✅ Ditemukan **{len(subdomains)}** subdomain!\n\n" + "\n".join(f"  • {d}" for d in subdomains[:25])
        return "ℹ️  Tidak ada subdomain tambahan ditemukan (mungkin terbatas)"

    def tool_dns_enum(self, target: str):
        rec = Recon(target)
        rec._dns_enum()
        dns = rec.results.get("dns", {})
        self.context["recon"]["dns"] = dns
        lines = []
        for qtype, records in dns.items():
            if records:
                lines.append(f"  **{qtype}:** " + ", ".join(records[:8]))
        if lines:
            return "📋 **DNS Records:**\n" + "\n".join(lines)
        return "ℹ️  Tidak ada DNS records"

    def tool_whois_lookup(self, target: str):
        rec = Recon(target)
        rec._whois_lookup()
        whois = rec.results.get("whois", {})
        self.context["recon"]["whois"] = whois
        if whois:
            self.context["target"] = target
            return "🏢 **WHOIS Info:**\n" + "\n".join(f"  • **{k}:** {v}" for k, v in whois.items())
        return "ℹ️  WHOIS tidak tersedia untuk target ini"

    def tool_nmap_scan(self, target: str, ports: str = ""):
        sc = Scanner([target])
        if ports:
            r = run_command(["nmap", "-T4", "-p", ports, "-oG", "-", target], timeout=300)
        else:
            r = run_command(["nmap", "-T4", "--top-ports", "1000", "-oG", "-", target], timeout=300)
        if not r["success"]:
            return f"❌ nmap gagal: {r['stderr'][:200]}"
        lines = []
        for line in r["stdout"].splitlines():
            if "/open/" in line:
                lines.append(line.strip())
        self.context["target"] = target
        if target not in self.context["targets"]:
            self.context["targets"].append(target)
        self.context["scan"]["open_ports"] = lines
        if lines:
            summary = f"🔓 **Ditemukan {len(lines)} port terbuka!**\n\n"
            for l in lines[:30]:
                parts = l.split()
                for p in parts:
                    m = __import__("re").match(r"(\d+)/open/(\w+)/{0,1}(.*)", p)
                    if m:
                        summary += f"  • Port **{m.group(1)}**/{m.group(2)} → {m.group(3) or 'unknown'}\n"
            return summary
        return "🔒 Tidak ada port terbuka (top 1000)"

    def tool_masscan_scan(self, target: str, ports: str = "1-10000", rate: int = 1000):
        if not which("masscan"):
            return "❌ masscan tidak terinstall. Coba pake nmap aja."
        r = run_command(["masscan", target, "--ports", ports, "--rate", str(rate), "-oJ", "/tmp/hunter_masscan.json"], timeout=120)
        if not r["success"]:
            return f"❌ masscan gagal: {r['stderr'][:200]}"
        try:
            with open("/tmp/hunter_masscan.json") as f:
                data = json.load(f)
            self.context["target"] = target
            if target not in self.context["targets"]:
                self.context["targets"].append(target)
            ports_found = []
            for e in data:
                for p in e.get("ports", []):
                    ports_found.append(f"{e.get('ip')}:{p.get('port')}/{p.get('proto', 'tcp')}")
            self.context["scan"]["open_ports"] = ports_found
            if ports_found:
                return f"⚡ **Masscan selesai!** Ditemukan **{len(ports_found)}** port:\n" + "\n".join(f"  • {x}" for x in ports_found[:30])
            return "🔒 Tidak ada port terbuka"
        except Exception as e:
            return f"❌ Error: {e}"

    def tool_service_detect(self, target: str, ports: str = ""):
        if not which("nmap"):
            return "❌ nmap tidak terinstall"
        cmd = ["nmap", "-sV", "-T4"]
        if ports:
            cmd.extend(["-p", ports])
        cmd.extend(["-oG", "-", target])
        r = run_command(cmd, timeout=300)
        if not r["success"]:
            return f"❌ nmap -sV gagal: {r['stderr'][:200]}"
        services = {}
        for line in r["stdout"].splitlines():
            if "/open/" in line:
                m = __import__("re").search(r"(\d+)/open/(\w+)/{0,1}(.*)", line)
                if m:
                    port = int(m.group(1))
                    svc = m.group(3).strip() if m.group(3) else "unknown"
                    services[port] = svc
        self.context["scan"]["services"] = services
        if services:
            return "🛠️ **Service Detection:**\n" + "\n".join(f"  • Port **{p}** → {s}" for p, s in services.items())
        return "ℹ️  Tidak ada service terdeteksi"

    def tool_nuclei_scan(self, target: str, severity: str = ""):
        if not which("nuclei"):
            return "❌ nuclei tidak terinstall. Install dulu: https://github.com/projectdiscovery/nuclei"
        cmd = ["nuclei", "-u", target, "-silent", "-json", "-rl", "50", "-t", "~/.local/nuclei-templates/"]
        if severity:
            cmd.extend(["-severity", severity])
        r = run_command(cmd, timeout=300)
        if not r["success"] and r["stderr"] and "COMMAND_NOT_FOUND" not in r["stderr"]:
            # Coba tanpa template path
            cmd2 = ["nuclei", "-u", target, "-silent", "-json", "-rl", "50"]
            if severity:
                cmd2.extend(["-severity", severity])
            r = run_command(cmd2, timeout=300)
        if not r["success"]:
            return f"❌ nuclei gagal: {r['stderr'][:200]}"
        findings = []
        for line in r["stdout"].splitlines():
            try:
                findings.append(json.loads(line))
            except Exception:
                findings.append({"raw": line})
        self.context["scan"]["nuclei"] = findings
        if findings:
            by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for f in findings:
                sev = f.get("info", {}).get("severity", "info").lower()
                by_severity[sev] = by_severity.get(sev, 0) + 1
            summary = f"🚨 **Nuclei Scan Selesai!** Ditemukan **{len(findings)}** vulnerability:\n"
            sev_str = " | ".join(f"{k.upper()}: {v}" for k, v in by_severity.items() if v > 0)
            summary += f"   {sev_str}\n\n"
            for f in findings[:10]:
                name = f.get("info", {}).get("name", f.get("template-id", "?"))
                sev = f.get("info", {}).get("severity", "?").upper()
                url = f.get("matched-at", "")
                summary += f"  • **[{sev}]** {name}\n    `{url}`\n"
            return summary
        return "✅ **Aman!** Tidak ada vulnerability ditemukan oleh nuclei."

    def tool_gobuster_dir(self, url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt"):
        if not which("gobuster"):
            return "❌ gobuster tidak terinstall"
        r = run_command(["gobuster", "dir", "-u", url, "-w", wordlist, "-t", "30", "-q"], timeout=180)
        if not r["success"]:
            return f"❌ gobuster gagal: {r['stderr'][:200]}"
        lines = [l.strip() for l in r["stdout"].splitlines() if l.strip()]
        self.context["web"]["directories"] = lines[:50]
        if lines:
            return f"📂 **Ditemukan {len(lines)} direktori/file!**\n\n" + "\n".join(f"  • `{l}`" for l in lines[:25])
        return "🔍 Tidak ada direktori tambahan ditemukan"

    def tool_ffuf_fuzz(self, url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt"):
        if not which("ffuf"):
            return "❌ ffuf tidak terinstall"
        r = run_command(["ffuf", "-u", url, "-w", wordlist, "-t", "30", "-s"], timeout=180)
        if not r["success"]:
            return f"❌ ffuf gagal: {r['stderr'][:200]}"
        lines = [l.strip() for l in r["stdout"].splitlines() if l.strip()]
        self.context["web"]["ffuf"] = lines[:30]
        if lines:
            return f"🎯 **Ffuf selesai!** Ditemukan {len(lines)} hasil:\n\n" + "\n".join(f"  • `{l}`" for l in lines[:20])
        return "🔍 ffuf selesai, tidak ada hasil"

    def tool_whatweb_detect(self, target: str):
        if not which("whatweb"):
            return "❌ whatweb tidak terinstall"
        r = run_command(["whatweb", target, "--aggression", "1"], timeout=60)
        if r["success"]:
            result = r["stdout"].strip()
            self.context["web"]["tech_stack"] = result
            return f"🌐 **Technology Stack:**\n{result[:600]}"
        return f"❌ whatweb gagal: {r['stderr'][:200]}"

    def tool_tech_stack(self, target: str):
        return self.tool_whatweb_detect(target)

    def tool_searchsploit_lookup(self, search: str):
        if not which("searchsploit"):
            return "❌ searchsploit tidak terinstall. Install exploit-db package."
        r = run_command(["searchsploit", search, "--json"], timeout=30)
        if not r["success"]:
            return f"❌ searchsploit gagal: {r['stderr'][:200]}"
        try:
            data = json.loads(r["stdout"])
            results = data.get("RESULTS_EXPLOIT", [])
            if results:
                lines = []
                for e in results[:15]:
                    title = e.get("Title", "?")
                    path = e.get("Path", "?")
                    edb_id = e.get("EDB-ID", "")
                    lines.append(f"  • **{title}**\n    ID: {edb_id} | `{path}`")
                self.context["exploit"]["searchsploit"] = results[:15]
                return f"💥 **Ditemukan {len(results)} exploit!**\n\n" + "\n".join(lines)
            return "📭 Tidak ada exploit ditemukan untuk pencarian itu"
        except Exception as e:
            return f"❌ Error: {e}"

    def tool_ai_analyze(self, data: str):
        from core.llm_client import LLMClient
        llm = LLMClient()
        system = "Kamu adalah AI Security Analyst expert. Analisis data penetration testing berikut. Berikan: 1) Ringkasan temuan 2) Kerentanan kritis 3) Rekomendasi langkah selanjutnya 4) Potensi exploit. Jawab dalam bahasa Indonesia yang gaul dan easy going."
        return llm.query(system + f"\n\nData:\n{data}")

    def tool_generate_report(self, format: str = "markdown"):
        from reporting.report import Report
        rpt = Report(self.context, f"hunter_{self.context['target'] or 'unknown'}")
        rpt.generate()
        return f"📄 **Laporan siap!**\n  • Markdown: `{rpt.output_file}`\n  • JSON: tersedia di folder reports/"

    def tool_show_context(self):
        c = self.context
        lines = ["📊 **Status Testing:**\n"]
        if c["target"]:
            lines.append(f"  🎯 **Target:** {c['target']}")
        if c["recon"]["subdomains"]:
            lines.append(f"  🌐 **Subdomain:** {len(c['recon']['subdomains'])} ditemukan")
        if c["recon"]["whois"]:
            lines.append(f"  🏢 **WHOIS:** tersedia")
        if c["scan"]["open_ports"]:
            lines.append(f"  🔓 **Open ports:** {len(c['scan']['open_ports'])}")
        if c["scan"]["services"]:
            lines.append(f"  🛠️ **Services:** {len(c['scan']['services'])} terdeteksi")
        if c["scan"]["nuclei"]:
            sevs = {}
            for f in c["scan"]["nuclei"]:
                s = f.get("info", {}).get("severity", "unknown").lower()
                sevs[s] = sevs.get(s, 0) + 1
            sev_str = ", ".join(f"{k.upper()}: {v}" for k, v in sevs.items())
            lines.append(f"  🚨 **Vulnerabilities:** {len(c['scan']['nuclei'])} ({sev_str})")
        if c["web"]["directories"]:
            lines.append(f"  📂 **Directories:** {len(c['web']['directories'])} ditemukan")
        if c["web"]["tech_stack"]:
            lines.append(f"  🌐 **Tech stack:** terdeteksi")
        if c["exploit"]["searchsploit"]:
            lines.append(f"  💥 **Exploit:** {len(c['exploit']['searchsploit'])} ditemukan")
        lines.append(f"\n  📜 **Tools dijalankan:** {len(c['history'])}x")
        return "\n".join(lines)

    def tool_auto_workflow(self, target: str):
        self.context["target"] = target
        if target not in self.context["targets"]:
            self.context["targets"].append(target)
        results = []
        steps = [
            ("subdomain_enum", {"domain": target}),
            ("dns_enum", {"target": target}),
            ("nmap_scan", {"target": target}),
            ("whatweb_detect", {"target": f"https://{target}"}),
        ]
        for tool_name, params in steps:
            results.append(f"\n─── {tool_name} ───")
            r = self.run_tool(tool_name, params)
            results.append(r)
        return "\n".join(results)

    def tool_file_read(self, path: str = "", **kwargs):
        if not path:
            return "❌ Kasih path file-nya dulu"
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            if len(content) > 5000:
                content = content[:5000] + f"\n\n... (truncated, total {len(content)} chars)"
            return f"📄 **{path}**\n\n```\n{content}\n```"
        except FileNotFoundError:
            return f"❌ File tidak ditemukan: {path}"
        except IsADirectoryError:
            return f"❌ Itu direktori, bukan file. Pake `file_list` buat list isinya"
        except Exception as e:
            return f"❌ Gagal baca file: {e}"

    def tool_file_list(self, path: str = ".", **kwargs):
        import os
        try:
            entries = os.listdir(path)
            entries.sort()
            files = []
            dirs = []
            for e in entries:
                full = os.path.join(path, e)
                if os.path.isdir(full):
                    dirs.append(f"📁 {e}/")
                else:
                    size = os.path.getsize(full)
                    if size < 1024:
                        sz = f"{size} B"
                    elif size < 1024 * 1024:
                        sz = f"{size/1024:.1f} KB"
                    else:
                        sz = f"{size/(1024*1024):.1f} MB"
                    files.append(f"📄 {e} ({sz})")
            result = f"📂 **{path}/**\n\n"
            if dirs:
                result += "─" * 30 + "\n" + "\n".join(dirs) + "\n"
            if files:
                result += "─" * 30 + "\n" + "\n".join(files) + "\n"
            if not entries:
                result += "(kosong)"
            return result
        except FileNotFoundError:
            return f"❌ Direktori tidak ditemukan: {path}"
        except Exception as e:
            return f"❌ Gagal list direktori: {e}"

    def tool_file_search(self, pattern: str = "", path: str = ".", **kwargs):
        import os
        import fnmatch
        if not pattern:
            return "❌ Kasih pattern file-nya dulu (contoh: `*.py`)"
        try:
            # Kalo path adalah file, ganti ke direktori parent-nya
            if os.path.isfile(path):
                path = os.path.dirname(path)
            if not os.path.isdir(path):
                return f"❌ Direktori tidak valid: {path}"
            matches = []
            for root, dirs, files in os.walk(path):
                dirs[:] = [d for d in dirs if not d.startswith('.') and d != '__pycache__']
                for f in files:
                    if fnmatch.fnmatch(f, pattern):
                        full = os.path.join(root, f)
                        rel = os.path.relpath(full, path)
                        size = os.path.getsize(full)
                        matches.append(f"  📄 {rel} ({size} B)")
                    if len(matches) >= 50:
                        break
                if len(matches) >= 50:
                    break
            if not matches:
                return f"❌ Tidak ada file matching `{pattern}` di `{path}`"
            result = f"🔍 **Ditemukan {len(matches)} file** matching `{pattern}`:\n\n"
            result += "\n".join(matches)
            if len(matches) >= 50:
                result += "\n  ... (max 50)"
            return result
        except Exception as e:
            return f"❌ Gagal search: {e}"

    def tool_none(self, **kwargs):
        return ""

    @staticmethod
    def _wiener_attack(n: int, e: int) -> int | None:
        """Wiener's continued fraction attack — cari d kecil."""
        def continued_fraction(num: int, den: int):
            while den:
                a = num // den
                yield a
                num, den = den, num - a * den

        def convergents(cf):
            n_prev, n_curr = 0, 1
            d_prev, d_curr = 1, 0
            for a in cf:
                n_prev, n_curr = n_curr, a * n_curr + n_prev
                d_prev, d_curr = d_curr, a * d_curr + d_prev
                yield n_curr, d_curr

        for k, d in convergents(continued_fraction(e, n)):
            if k == 0:
                continue
            if (e * d - 1) % k != 0:
                continue
            phi = (e * d - 1) // k
            # cari p, q dari phi
            # n = p*q, phi = (p-1)*(q-1) = n - p - q + 1
            # p + q = n - phi + 1
            s = n - phi + 1
            discriminant = s * s - 4 * n
            if discriminant < 0:
                continue
            sqrt_disc = isqrt(discriminant)
            if sqrt_disc * sqrt_disc != discriminant:
                continue
            p = (s + sqrt_disc) // 2
            q = (s - sqrt_disc) // 2
            if p * q == n:
                return d
        return None

    @staticmethod
    def _fermat_factor(n: int) -> tuple | None:
        a = isqrt(n)
        if a * a < n:
            a += 1
        for _ in range(1000000):
            b2 = a * a - n
            b = isqrt(b2)
            if b * b == b2:
                return (a - b, a + b)
            a += 1
        return None

    @staticmethod
    def _try_decrypt(c: int, d: int, n: int) -> str | None:
        try:
            pt = pow(c, d, n)
            pt_bytes = pt.to_bytes((pt.bit_length() + 7) // 8, "big")
            # Cek flag pattern langsung di bytes (semua format umum)
            for pat in (b"flag{", b"CTF{", b"FLAG{", b"bounty{", b"comnetics{", b"COMNETICS{", b"hacktiv{", b"HACKTIV{", b"jr1{", b"skid{"):
                if pat in pt_bytes:
                    idx = pt_bytes.index(pat)
                    end = pt_bytes.index(b"}", idx) + 1 if b"}" in pt_bytes[idx:] else len(pt_bytes)
                    return pt_bytes[idx:end].decode("latin-1")
            # Coba decode
            for enc in ("utf-8", "latin-1"):
                try:
                    decoded = pt_bytes.decode(enc)
                    if decoded.isprintable() and len(decoded) > 3:
                        return decoded.strip()
                except Exception:
                    pass
            # Hex decode
            h = hex(pt)[2:]
            if len(h) % 2 == 0:
                try:
                    decoded = bytes.fromhex(h).decode("latin-1")
                    for pat in ("flag{", "ctf{", "bounty{"):
                        if pat in decoded.lower():
                            return decoded.strip()
                except Exception:
                    pass
        except Exception:
            pass
        return None

    @staticmethod
    def _solve_rsa_from_text(content: str) -> str | None:
        """Parse RSA params dari teks dan coba decrypt. Return flag kalo berhasil."""
        ints = {}
        for key in ("n", "e", "c", "d", "hint", "p", "q", "dp", "dq", "phi", "r", "s", "x"):
            m = re.search(rf'\b{key}\s*[=:]\s*(\d+)', content, re.IGNORECASE)
            if m:
                ints[key] = int(m.group(1))

        if "n" not in ints or "c" not in ints:
            return None
        if "e" not in ints:
            ints["e"] = 65537

        n = ints["n"]
        e = ints["e"]
        c = ints["c"]
        d = None

        # 1. Langsung pake d
        if "d" in ints:
            result = ToolRegistry._try_decrypt(c, ints["d"], n)
            if result:
                return result

        # 2. Hint sebagai d
        if "hint" in ints:
            result = ToolRegistry._try_decrypt(c, ints["hint"], n)
            if result:
                return result

        # 3. Hint sebagai phi
        if "hint" in ints:
            try:
                d2 = pow(e, -1, ints["hint"])
                result = ToolRegistry._try_decrypt(c, d2, n)
                if result:
                    return result
            except Exception:
                pass

        # 4. Hint sebagai p (factor)
        if "hint" in ints and n % ints["hint"] == 0:
            p = ints["hint"]
            q = n // p
            phi = (p - 1) * (q - 1)
            d = pow(e, -1, phi)
            result = ToolRegistry._try_decrypt(c, d, n)
            if result:
                return result

        # 5. Known p/q
        if "p" in ints and n % ints["p"] == 0:
            p = ints["p"]
            q = n // p
            phi = (p - 1) * (q - 1)
            d = pow(e, -1, phi)
            result = ToolRegistry._try_decrypt(c, d, n)
            if result:
                return result
        if "q" in ints and n % ints["q"] == 0:
            q = ints["q"]
            p = n // q
            phi = (p - 1) * (q - 1)
            d = pow(e, -1, phi)
            result = ToolRegistry._try_decrypt(c, d, n)
            if result:
                return result

        # 6. Wiener attack
        d = ToolRegistry._wiener_attack(n, e)
        if d:
            result = ToolRegistry._try_decrypt(c, d, n)
            if result:
                return result

        # 7. Fermat factorization (close p, q)
        fermat = ToolRegistry._fermat_factor(n)
        if fermat:
            p, q = fermat
            phi = (p - 1) * (q - 1)
            d = pow(e, -1, phi)
            result = ToolRegistry._try_decrypt(c, d, n)
            if result:
                return result

        # 8. Small e attack (plaintext^e = c, no mod reduction)
        if e <= 7 and pow(2, e) > n:
            for k in range(1, 1000):
                m = k * n + c
                root = round(m ** (1.0 / e))
                for delta in range(-2, 3):
                    candidate = root + delta
                    if candidate > 0 and pow(candidate, e) == m:
                        pt_bytes = candidate.to_bytes((candidate.bit_length() + 7) // 8, "big")
                        try:
                            decoded = pt_bytes.decode("latin-1")
                            if decoded.isprintable() or "flag{" in decoded.lower():
                                return decoded.strip()
                            elif len(pt_bytes) < 200:
                                return decoded.strip()
                        except Exception:
                            pass
                        break

        # 9. Hint sebagai dp (e * dp ≡ 1 mod (p-1))
        if "hint" in ints and e > 1:
            hint = ints["hint"]
            for k in range(1, 100000):
                if (e * hint - 1) % k == 0:
                    p_minus_1 = (e * hint - 1) // k
                    p = p_minus_1 + 1
                    if n % p == 0:
                        q = n // p
                        phi = (p - 1) * (q - 1)
                        d = pow(e, -1, phi)
                        result = ToolRegistry._try_decrypt(c, d, n)
                        if result:
                            return result

        return None

    def _extract_and_analyze(self, path: str, results: list, depth: int = 0) -> bool:
        """Extract archive dan analisis isinya. Return True kalo nemu flag."""
        if depth > 3:
            return False
        temp_dir = f"/tmp/hunter_extract_{os.getpid()}_{depth}"
        run_command(["rm", "-rf", temp_dir], timeout=5)
        os.makedirs(temp_dir, exist_ok=True)

        found = False
        filetype = ""
        r0 = run_command(["file", "-b", path], timeout=10)
        if r0["success"]:
            filetype = r0["stdout"].strip().lower()

        extract_ok = False
        if "zip" in filetype:
            r = run_command(["unzip", "-o", path, "-d", temp_dir], timeout=30)
            extract_ok = r["success"]
        elif "gzip" in filetype or "bzip2" in filetype or "xz" in filetype or "tar" in filetype:
            r = run_command(["tar", "-xf", path, "-C", temp_dir], timeout=30)
            extract_ok = r["success"]
        elif "rar" in filetype:
            r = run_command(["unrar", "x", "-y", path, f"{temp_dir}/"], timeout=30)
            extract_ok = r["success"]
        elif "7-zip" in filetype or "7z" in filetype:
            r = run_command(["7z", "x", path, f"-o{temp_dir}", "-y"], timeout=30)
            extract_ok = r["success"]

        if not extract_ok:
            run_command(["rm", "-rf", temp_dir], timeout=5)
            return False

        extracted = []
        for root, dirs, files in os.walk(temp_dir):
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            for f in files:
                extracted.append(os.path.join(root, f))

        if not extracted:
            run_command(["rm", "-rf", temp_dir], timeout=5)
            return False

        indent = "  " * (depth + 1)
        results.append(f"\n{indent}📂 **Isi arsip** ({len(extracted)} file):")
        for ef in extracted[:30]:
            rel = os.path.relpath(ef, temp_dir)
            sz = os.path.getsize(ef)
            results.append(f"{indent}  • {rel} ({sz} B)")

        flag_patterns = ("flag{", "ctf{", "bounty{", "FLAG{", "CTF{", "comnetics{", "COMNETICS{", "hacktiv{", "jr1{", "skid{")
        text_exts = {".txt", ".md", ".py", ".sh", ".html", ".php", ".js", ".xml", ".json", ".yml", ".yaml", ".conf", ".cfg", ".ini", ".log", ".csv", ".sql", ".rb", ".pl", ".go", ".rs", ".c", ".h", ".cpp", ".java", ".lua"}
        img_exts = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".webp", ".ico"}

        # Prioritaskan file kecil dulu (flag biasanya kecil)
        extracted.sort(key=lambda f: os.path.getsize(f))

        for ef in extracted:
            ext = os.path.splitext(ef)[1].lower()
            fsize = os.path.getsize(ef)
            frel = os.path.relpath(ef, temp_dir)

            # Text files — baca langsung
            if ext in text_exts or fsize < 50000:
                try:
                    with open(ef, "r", encoding="utf-8", errors="replace") as fh:
                        content = fh.read()
                    for pat in flag_patterns:
                        if pat in content:
                            found = True
                            # Extract line yang mengandung flag
                            for line in content.splitlines():
                                if pat in line:
                                    results.append(f"\n{indent}🏴 **FLAG ditemukan di `{frel}`:** `{line.strip()}`")
                            break
                    # Kalo gak ada flag tapi readable, tampilkan isinya (kalo kecil)
                    if not found and fsize < 2000:
                        results.append(f"\n{indent}📄 **{frel}:**```\n{content.strip()[:1000]}\n```")
                    # Coba solve RSA challenge kalo kontennya mengandung RSA params
                    if not found and re.search(r'\bn\s*[=:]\s*\d+', content) and re.search(r'\bc\s*[=:]\s*\d+', content):
                        flag = self._solve_rsa_from_text(content)
                        if flag:
                            found = True
                            results.append(f"\n{indent}🏴 **FLAG (RSA decrypted):** `{flag}`")
                        else:
                            results.append(f"\n{indent}🔐 **RSA challenge detected** — mencoba berbagai attack tapi belum berhasil. Manual decrypt mungkin diperlukan.")
                except Exception:
                    # Fallback ke strings
                    rs = run_command(["strings", ef], timeout=15)
                    if rs["success"]:
                        for pat in flag_patterns:
                            if pat in rs["stdout"]:
                                found = True
                                for line in rs["stdout"].splitlines():
                                    if pat in line:
                                        results.append(f"\n{indent}🏴 **FLAG ditemukan di `{frel}`:** `{line.strip()}`")
                                break
                        # Coba solve RSA dari strings output
                        if not found and "n=" in rs["stdout"].replace(" ", "") and "c=" in rs["stdout"].replace(" ", ""):
                            flag = self._solve_rsa_from_text(rs["stdout"])
                            if flag:
                                found = True
                                results.append(f"\n{indent}🏴 **FLAG (RSA decrypted):** `{flag}`")

            # Image files — stego analysis
            if ext in img_exts:
                results.append(f"\n{indent}🖼️ **Analisa gambar: {frel}**")
                rs = run_command(["strings", ef], timeout=15)
                if rs["success"]:
                    for pat in flag_patterns:
                        if pat in rs["stdout"]:
                            found = True
                            for line in rs["stdout"].splitlines():
                                if pat in line:
                                    results.append(f"{indent}  🏴 **FLAG di gambar:** `{line.strip()}`")
                            break
                # exiftool on image
                rx = run_command(["exiftool", ef], timeout=15)
                if rx["success"]:
                    meta = [l.strip() for l in rx["stdout"].splitlines() if l.strip() and ":" in l]
                    flag_meta = [l for l in meta if any(p in l.lower() for p in ("flag", "ctf", "secret", "hidden"))]
                    if flag_meta:
                        found = True
                        for l in flag_meta:
                            results.append(f"{indent}  🏴 **Flag di metadata:** {l}")
                    elif meta:
                        results.append(f"{indent}  📋 Metadata: {len(meta)} entries")

            # Archive in archive — rekursif
            if ext in {".zip", ".tar", ".gz", ".bz2", ".xz", ".rar", ".7z"}:
                sub_found = self._extract_and_analyze(ef, results, depth + 1)
                if sub_found:
                    found = True

            if found:
                break

        # String search semua binary files yang belum di-scan
        if not found:
            for ef in extracted:
                ext = os.path.splitext(ef)[1].lower()
                if ext not in text_exts and ext not in img_exts and ext not in {".zip", ".tar", ".gz", ".bz2", ".xz", ".rar", ".7z"}:
                    rs = run_command(["strings", "-n", "8", ef], timeout=15)
                    if rs["success"]:
                        for pat in flag_patterns:
                            if pat in rs["stdout"]:
                                found = True
                                frel = os.path.relpath(ef, temp_dir)
                                for line in rs["stdout"].splitlines():
                                    if pat in line:
                                        results.append(f"\n{indent}🏴 **FLAG di `{frel}`:** `{line.strip()}`")
                                break
                    if found:
                        break

        # Cek juga dengan grep di seluruh hasil extract kalo belum nemu
        if not found:
            rg = run_command(["grep", "-rl", "--include=*", "-e", "flag{", "-e", "CTF{", "-e", "bounty{", temp_dir], timeout=30)
            if rg["success"] and rg["stdout"].strip():
                found = True
                for match in rg["stdout"].splitlines():
                    frel = os.path.relpath(match, temp_dir)
                    try:
                        with open(match, "r") as fh:
                            for line in fh:
                                if any(p in line for p in flag_patterns):
                                    results.append(f"\n{indent}🏴 **FLAG ditemukan di `{frel}`:** `{line.strip()}`")
                                    break
                    except Exception:
                        pass

        run_command(["rm", "-rf", temp_dir], timeout=5)
        return found

    def tool_stego_analyze(self, path: str = "", **kwargs):
        if not path:
            return "❌ Kasih path file-nya dulu"
        if not os.path.isfile(path):
            return f"❌ File tidak ditemukan: {path}"

        results = [f"🔍 **Deep Analysis: {path}**"]
        found_anything = False

        # 0. file type
        r0 = run_command(["file", path], timeout=10)
        if r0["success"]:
            results.append(f"\n📁 **File type:** {r0['stdout'].strip()}")

        # 1. strings — langsung cari flag pattern
        r = run_command(["strings", "-n", "6", path], timeout=30)
        if r["success"] and r["stdout"].strip():
            lines = r["stdout"].splitlines()
            flag_lines = [l for l in lines if any(k in l.lower() for k in ("flag{", "ctf{", "bounty{", "secret{", "hidden{"))]
            if flag_lines:
                found_anything = True
                results.append(f"\n🏴 **Flag-like strings:**```\n" + "\n".join(flag_lines[:20]) + "```")
            longer = [l for l in lines if len(l) > 12]
            if longer:
                results.append(f"\n📝 **Strings ({len(longer)} ditemukan):**\n  " + "\n  ".join(longer[:25]))

        # 2. exiftool
        r2 = run_command(["exiftool", path], timeout=30)
        if r2["success"]:
            meta = [l.strip() for l in r2["stdout"].splitlines() if l.strip() and ":" in l]
            flag_meta = [l for l in meta if any(p in l.lower() for p in ("flag", "ctf", "secret", "hidden", "comment", "description"))]
            if flag_meta:
                found_anything = True
                results.append(f"\n🏴 **Flag di metadata:**```\n" + "\n".join(flag_meta) + "```")
            if meta:
                results.append(f"\n📋 **Metadata ({len(meta)} entries):**```\n" + "\n".join(meta[:20]) + "```")

        # 3. Extract & analyze archive (kalo file adalah arsip)
        is_archive = False
        if r0["success"]:
            ft = r0["stdout"].lower()
            is_archive = any(k in ft for k in ("zip", "tar", "gzip", "bzip2", "xz", "rar", "7-zip", "compress", "archive"))
        if is_archive:
            results.append(f"\n📦 **Arsip terdeteksi — mengekstrak dan menganalisis...**")
            found_in_archive = self._extract_and_analyze(path, results, 0)
            if found_in_archive:
                found_anything = True

        # 4. steghide (skip kalo bukan image/audio)
        if r0["success"]:
            ft = r0["stdout"].lower()
            if any(k in ft for k in ("image", "jpeg", "png", "bmp", "gif", "audio", "wav", "mp3")):
                r_steghide = run_command(["steghide", "extract", "-sf", path, "-p", ""], timeout=15)
                if r_steghide["success"]:
                    found_anything = True
                    results.append(f"\n🔐 **Steghide:** Berhasil ekstrak data tersembunyi!")
                    # Baca hasil extract
                    for sf in os.listdir("."):
                        if os.path.isfile(sf) and not sf.startswith("."):
                            try:
                                with open(sf) as fh:
                                    content = fh.read()
                                if any(p in content for p in ("flag{", "ctf{", "bounty{")):
                                    results.append(f"  🏴 **Flag:** {content.strip()}")
                                os.remove(sf)
                            except Exception:
                                pass

        # 5. foremost — file carving (skip kalo udah di-extract)
        if not is_archive:
            carve_dir = f"/tmp/hunter_foremost_{os.getpid()}"
            r3 = run_command(["foremost", "-t", "all", "-i", path, "-o", carve_dir], timeout=60)
            if r3["success"]:
                carved_files = []
                for root, dirs, files in os.walk(carve_dir):
                    for f in files:
                        carved_files.append(os.path.join(root, f))
                # Cari flag di carved files
                for cf in carved_files[:20]:
                    rs = run_command(["strings", cf], timeout=10)
                    if rs["success"]:
                        for line in rs["stdout"].splitlines():
                            if any(k in line.lower() for k in ("flag{", "ctf{", "bounty{")):
                                found_anything = True
                                results.append(f"\n🧩 **Foremost — Flag:** `{line.strip()}`")
                carved_count = len(carved_files)
                if carved_count:
                    results.append(f"\n🧩 **Foremost:** {carved_count} file di-recover")
                run_command(["rm", "-rf", carve_dir], timeout=5)

        # 6. binwalk
        if not is_archive:
            r4 = run_command(["binwalk", "-Me", "-q", "-C", f"/tmp/hunter_binwalk_{os.getpid()}", path], timeout=60)
            if r4["success"] and r4["stdout"].strip():
                for line in r4["stdout"].splitlines():
                    if any(k in line.lower() for k in ("flag", "ctf", "secret")):
                        found_anything = True
                        results.append(f"\n🧩 **Binwalk:** `{line.strip()}`")
                        break
                results.append(f"\n🧩 **Binwalk:** scan selesai")

        # 7. Info ukuran
        size = os.path.getsize(path)
        results.append(f"\n📊 **Size:** {size} bytes ({size/1024:.1f} KB)")

        if not found_anything:
            # AI-powered deep analysis (kalo ada LLM tersedia)
            try:
                from core.llm_client import LLMClient
                llm = LLMClient()
                if llm.is_available():
                    # Kumpulin data mentah dari file
                    raw_data = []
                    raw_data.append(f"File: {path}")
                    raw_data.append(f"Size: {size} bytes")
                    if r0["success"]:
                        raw_data.append(f"Type: {r0['stdout'].strip()}")

                    # Baca isi file kalo teks
                    text_content = ""
                    try:
                        with open(path, "r", encoding="utf-8", errors="replace") as fh:
                            text_content = fh.read(5000)
                    except Exception:
                        pass

                    # Kalo arsip, coba baca file-file di dalamnya
                    extracted_texts = []
                    if is_archive:
                        tmp = f"/tmp/hunter_ai_{os.getpid()}"
                        run_command(["rm", "-rf", tmp], timeout=5)
                        os.makedirs(tmp, exist_ok=True)
                        if "zip" in ft:
                            run_command(["unzip", "-o", path, "-d", tmp], timeout=30)
                        elif "tar" in ft or "gzip" in ft or "bzip2" in ft:
                            run_command(["tar", "-xf", path, "-C", tmp], timeout=30)
                        for root, dirs, files in os.walk(tmp):
                            for f in files:
                                fp = os.path.join(root, f)
                                try:
                                    with open(fp, "r", encoding="utf-8", errors="replace") as fh:
                                        c = fh.read(3000)
                                        if c.strip():
                                            extracted_texts.append(f"--- {f} ---\n{c}")
                                except Exception:
                                    rs = run_command(["strings", fp], timeout=10)
                                    if rs["success"] and rs["stdout"].strip():
                                        extracted_texts.append(f"--- {f} (strings) ---\n{rs['stdout'][:500]}")
                        run_command(["rm", "-rf", tmp], timeout=5)

                    # Kalo strings output berguna, kirim juga
                    strings_data = ""
                    if r["success"] and r["stdout"].strip():
                        strings_data = r["stdout"][:2000]

                    # Bangun prompt buat AI
                    ai_data = "\n".join(raw_data)
                    if text_content:
                        ai_data += f"\n\n=== ISI FILE ===\n{text_content[:3000]}"
                    if extracted_texts:
                        ai_data += f"\n\n=== ISI EKSTRAK ===\n" + "\n".join(extracted_texts[:5])
                    if strings_data and not text_content:
                        ai_data += f"\n\n=== STRINGS ===\n{strings_data}"

                    # Minta AI analisis langsung
                    prompt = f"""Kamu CTF expert. Cari flag dari file berikut. Analisis dan jawab.

{ai_data}

Tugas: cari flag. Kalo nemu flag, tulis persis format flag-nya. Kalo belum nemu, analisis dan kasih langkah berikutnya."""
                    msgs = [
                        {"role": "system", "content": "Kamu adalah CTF expert. Cari flag dari data yang diberikan. Jawab dalam bahasa Indonesia."},
                        {"role": "user", "content": prompt}
                    ]
                    for cfg in llm.router._fallback_chain:
                        fn = __import__('core.llm_router', fromlist=['']).__dict__.get(cfg["check_fn"])
                        if fn and not fn(cfg):
                            continue
                        qfn = __import__('core.llm_router', fromlist=['']).__dict__.get(cfg["query_fn"])
                        if qfn:
                            try:
                                r = qfn(cfg, msgs, llm.router.model)
                                results.append(f"\n🤖 **AI Analysis:**\n{r[:1500]}")
                                break
                            except Exception:
                                continue
            except Exception:
                pass

            results.append(f"\n❌ **Flag tidak ditemukan** dengan metode yang tersedia.")
        else:
            results.append(f"\n✅ **Analisis selesai!** Flag berhasil ditemukan.")

        return "\n".join(results)
