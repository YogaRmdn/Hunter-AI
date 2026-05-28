import os
import re

IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
DOMAIN_PATTERN = re.compile(r'\b(?:https?://)?(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?::\d+)?(?:/\S*)?\b')
URL_PATTERN = re.compile(r'https?://[^\s]+')
PORT_RANGE_PATTERN = re.compile(r'(\d{1,5})-(\d{1,5})')

TOOL_TRIGGERS = {
    "subdomain_enum": [
        r'\bsubdomain\b', r'\bcari\s+domain\b', r'\benum\s+domain\b',
        r'\bfind\s+subdomain', r'\bdomain\s+enum',
    ],
    "dns_enum": [
        r'\bdns\b', r'\bmx\s+record', r'\bns\s+record', r'\btxt\s+record',
        r'\bsoa\b', r'\bdns\s+lookup', r'\bdig\b',
    ],
    "whois_lookup": [
        r'\bwhois\b', r'\bregistrar\b', r'\bpemilik\s+domain\b',
        r'\bsiapa\s+punya\b', r'\bdomain\s+info\b', r'\bkepemilikan\b',
    ],
    "nmap_scan": [
        r'\bnmap\b', r'\bscan\b', r'\bport\b', r'\bscanning\b',
        r'\bopen\s+port\b', r'\bcek\s+port\b',
    ],
    "masscan_scan": [
        r'\bmasscan\b', r'\bfast\s+scan\b', r'\bcepat\s+scan\b',
        r'\bkilat\b', r'\brange\s+port\b', r'\b1-65535\b', r'\bfull\s+port\b',
    ],
    "service_detect": [
        r'\bservice\b', r'\bdetect\s+service\b', r'\bversi\b',
        r'\bversion\b', r'\bwhat\s+service\b', r'\bservice\s+enum\b',
    ],
    "nuclei_scan": [
        r'\bnuclei\b', r'\bvuln\b', r'\bvulnerability\b', r'\bkerentanan\b',
        r'\bcve\b', r'\bcelah\b', r'\bweakness\b',
    ],
    "gobuster_dir": [
        r'\bgobuster\b', r'\bdir\s*bust', r'\bdirectory\b', r'\bfolder\b',
        r'\bdir\s*scan\b', r'\bdir\s+enum\b', r'\bpath\s+discovery\b',
        r'\bhidden\s+dir\b',
    ],
    "ffuf_fuzz": [
        r'\bffuf\b', r'\bfuzz\b', r'\bendpoint\b', r'\bvhost\b',
        r'\bparameter\s+fuzz\b',
    ],
    "whatweb_detect": [
        r'\bwhatweb\b', r'\bteknologi\b', r'\btech\s*stack\b',
        r'\bcms\b', r'\bframework\b', r'\btechnology\b',
        r'\bpake\s+apa\b', r'\bdibangun\s+dengan\b',
    ],
    "tech_stack": [
        r'\bteknologi\b', r'\btech\s*stack\b', r'\bcms\b',
        r'\bframework\b', r'\bpake\s+apa\b',
    ],
    "searchsploit_lookup": [
        r'\bsearchsploit\b', r'\bexploit\b', r'\bcari\s+exploit\b',
        r'\bfind\s+exploit\b', r'\bedb\b',
    ],
    "ai_analyze": [
        r'\banalis[ai]s\b', r'\banalyze\b', r'\banalisa\b',
        r'\brekomendasi\b', r'\bkesimpulan\b', r'\brangkum\b',
        r'\bsummarize\b',
    ],
    "generate_report": [
        r'\blaporan\b', r'\breport\b', r'\bbuat\s*(laporan|report)',
        r'\bgenerate\s*(laporan|report)', r'\bhasil\s+testing\b',
    ],
    "file_read": [
        r'\bbaca\s+file\b', r'\bbuka\s+file\b', r'\blhat\s+file\b',
        r'\bread\s+file\b', r'\btampilkan\s+file\b',
        r'\bisi\s+file\b', r'\btunjukin\s+file\b',
        r'\bbaca\s+/[\w/]', r'\bbaca\s+[\w./]+\.\w+\b',
        r'\bshow\s+file\b', r'\bshow\s+/[\w/]',
    ],
    "file_list": [
        r'\blist\s+(dir|directory)\b', r'\bls\b',
        r'\bapa\s+aja\s+di\b', r'\bisi\s+(dir|directory|folder)\b',
        r'\bdaftar\s+(file|isinya)\b', r'\bliat\s+(dir|directory)\b',
    ],
    "file_search": [
        r'\bcari\s+file\b', r'\bfind\s+file\b', r'\bsearch\s+file\b',
        r'\bglob\b', r'\bfnmatch\b', r'\bfile\s+pattern\b',
    ],
    "show_context": [
        r'\b(apa\s+aja|hasil|status|progress|state|konteks|tadi)\b',
        r'\bsudah\s+dilaku(in|kan)\b',
    ],
    "stego_analyze": [
        r'\bstego\b', r'\bflag\b', r'\bhidden\b', r'\bsembunyi\b',
        r'\bmetadata\b', r'\bexiftool\b', r'\bstrings\b',
        r'\bbinwalk\b', r'\bforemost\b', r'\bsteghide\b',
        r'\bfoto\b', r'\bgambar\b', r'\bimage\b', r'\bjpg\b', r'\bpng\b',
        r'\bcari\s+flag\b', r'\bflag\s+pada\b',
    ],
    "auto_workflow": [
        r'\btesting\b', r'\baudit\b',
        r'\bpenetration\b', r'\bsecurity\s+assessment\b',
        r'\bserangan\b', r'\bpengujian\b',
    ],
}

WORKFLOW_TRIGGERS = {
    "auto_workflow": [
        r'\brecon\b', r'\bgass?\b', r'\bhack\b',
        r'\bfull\s+scan\b', r'\bbobol\b', r'\bsantet\b',
    ],
}


def extract_target(text: str) -> str:
    m = re.search(r'https?://[^\s]+', text)
    if m:
        return m.group().rstrip('/')
    ips = IP_PATTERN.findall(text)
    if ips:
        valid = [ip for ip in ips if all(0 <= int(o) <= 255 for o in ip.split('.'))]
        if valid:
            return valid[0]
    domains = DOMAIN_PATTERN.findall(text)
    if domains:
        for d in domains:
            d = d.lower().strip()
            d = re.sub(r'^https?://', '', d)
            d = d.split('/')[0].split(':')[0]
            if '.' in d and not re.match(r'^\d+(\.\d+)+$', d):
                return d
    return ""


def extract_ports(text: str) -> str:
    has_ip = bool(IP_PATTERN.search(text))
    range_m = PORT_RANGE_PATTERN.search(text)
    if range_m:
        return f"{range_m.group(1)}-{range_m.group(2)}"

    # Kalo ada IP, cari "port XX,YY" atau "-p XX,YY" explicit
    if has_ip:
        m = re.search(r'\bport\b\s+([\d,\s]+)', text, re.IGNORECASE)
        if not m:
            m = re.search(r'-p\s+([\d,]+)', text)
        if m:
            nums = re.findall(r'\b(\d{2,5})\b', m.group(1))
            valid = [p for p in nums if 1 <= int(p) <= 65535]
            if valid:
                return ",".join(valid[:10])
        return ""

    # Tanpa IP, lebih fleksibel
    port_phrase = re.search(r'\bport\b\s+([\d,\s]+)|-p\s+([\d,]+)', text, re.IGNORECASE)
    if port_phrase:
        group = port_phrase.group(1) or port_phrase.group(2) or ""
        nums = re.findall(r'\b(\d{2,5})\b', group)
        valid = [p for p in nums if 1 <= int(p) <= 65535]
        if valid:
            return ",".join(valid[:10])
    return ""


def extract_url(text: str) -> str:
    m = URL_PATTERN.search(text)
    if m:
        return m.group().rstrip('/')
    return ""


def _build_tool_params(tool_name: str, text: str, text_lower: str) -> dict:
    params = {}
    target = extract_target(text)

    if tool_name in ("nmap_scan", "masscan_scan", "service_detect", "dns_enum", "whois_lookup", "auto_workflow"):
        if not target:
            ips = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', text)
            if ips:
                target = ips[0]
        if target:
            params["target"] = target
            if tool_name == "nmap_scan":
                ports = extract_ports(text)
                if ports:
                    params["ports"] = ports
    elif tool_name == "subdomain_enum":
        if not target:
            target = extract_target(text)
            if target and target.startswith("http"):
                target = re.sub(r'^https?://', '', target).split('/')[0]
        if target:
            params["domain"] = target
    elif tool_name in ("nuclei_scan",):
        target = extract_url(text) or extract_target(text)
        if target:
            if not target.startswith("http"):
                target = f"https://{target}"
            params["target"] = target
        sev = re.search(r'\b(critical|high|medium|low)\b', text_lower)
        if sev:
            params["severity"] = sev.group(1)
    elif tool_name in ("whatweb_detect", "tech_stack"):
        target = extract_url(text) or extract_target(text)
        if target:
            if not target.startswith("http"):
                target = f"https://{target}"
            params["target"] = target
    elif tool_name in ("gobuster_dir",):
        target = extract_url(text) or extract_target(text)
        if target:
            if not target.startswith("http"):
                target = f"http://{target}"
            params["url"] = target
    elif tool_name in ("ffuf_fuzz",):
        url = extract_url(text) or extract_target(text)
        if url:
            if not url.startswith("http"):
                url = f"http://{url}"
            if "FUZZ" not in url:
                url = url.rstrip('/') + "/FUZZ"
            params["url"] = url
    elif tool_name in ("searchsploit_lookup",):
        search_term = text
        for prefix in ["cari exploit", "search exploit", "exploit untuk", "cari"]:
            if prefix in text_lower:
                idx = text_lower.find(prefix) + len(prefix)
                search_term = text[idx:].strip().lstrip(": ")
                break
        params["search"] = search_term.strip() or target or text
    elif tool_name in ("file_read",):
        # Coba relative path dulu (path.extension), lalu absolute (/path)
        path_match = re.search(r'(?:file\s+)?([\w./\\-]+\.[a-zA-Z0-9]{1,4})(?:\s|$)', text)
        if path_match:
            params["path"] = path_match.group(1)
        else:
            path_match2 = re.search(r'(?:file\s+)?(/[^\s]+)', text)
            if path_match2:
                params["path"] = path_match2.group(1)
            else:
                path_match3 = re.search(r'(?:baca|read|lihat|tampilkan|buka|tunjukin)\s+(?:file\s+)?(.+)', text, re.IGNORECASE)
                if path_match3:
                    p = path_match3.group(1).strip().strip('"\'')
                    if p:
                        params["path"] = p
    elif tool_name in ("file_list",):
        path_match = re.search(r'(?:di|dir|folder|directory)\s+(/?(?:\w+/)*\w*)', text, re.IGNORECASE)
        if path_match:
            p = path_match.group(1).strip()
            if p and p != text:
                params["path"] = p
        if not params.get("path"):
            path_match2 = re.search(r'(?:list|ls)\s+(/?(?:\w+/)*\w*)', text, re.IGNORECASE)
            if path_match2:
                p = path_match2.group(1).strip()
                if p and p != text:
                    params["path"] = p
    elif tool_name in ("file_search",):
        m = re.search(r'(?:pattern\s+)?["\']([^"\']+)["\']', text)
        if m:
            params["pattern"] = m.group(1)
            path_m = re.search(r'(?:di|in|path)\s+(/?(?:\w+/)*\w+)', text, re.IGNORECASE)
            if path_m:
                params["path"] = path_m.group(1)
        else:
            m2 = re.search(r'(?:cari|find|search)\s+(?:file\s+)?(.+?)(?:\s+(?:di|in|path)\s+|$)', text, re.IGNORECASE)
            if m2:
                p = m2.group(1).strip()
                p = p.strip('"\'')
                if p:
                    params["pattern"] = p
            path_m = re.search(r'(?:di|in|path)\s+(/?(?:[^\s]+))', text, re.IGNORECASE)
            if path_m:
                params["path"] = path_m.group(1)
    elif tool_name in ("ai_analyze",):
        params["data"] = text
    elif tool_name in ("stego_analyze",):
        # Cari path file — handle berbagai format path
        # Prioritas: absolute path > relative path with ext > any path
        path_m = re.search(r'(?:foto|gambar|image|file|di)\s+(/[^\s]+)', text)
        if path_m:
            params["path"] = path_m.group(1)
        else:
            path_m2 = re.search(r'(?:foto|gambar|image|file|di)\s+([\w./\\-]+\.[a-zA-Z0-9]{1,6})', text)
            if path_m2:
                params["path"] = path_m2.group(1)
            else:
                path_m3 = re.search(r'(/[^\s]+\.[a-zA-Z0-9]{1,6})', text)
                if path_m3:
                    params["path"] = path_m3.group(1)
                else:
                    # Fallback: anything that looks like a path with an extension
                    path_m4 = re.search(r'([\w./\\-]+\.(?:[a-zA-Z0-9]{1,6}))', text)
                    if path_m4:
                        params["path"] = path_m4.group(1)
                    else:
                        # Last resort: absolute path without extension
                        path_m5 = re.search(r'(/[^\s]+)', text)
                        if path_m5:
                            candidate = path_m5.group(1)
                            if os.path.isfile(candidate):
                                params["path"] = candidate
    elif tool_name in ("generate_report",):
        params["format"] = "json" if "json" in text_lower else "markdown"
    return params


def parse(text: str) -> dict:
    text_clean = text.strip()
    text_lower = text_clean.lower()

    # Check specific tool triggers
    matched_tools = set()
    for tool_name, patterns in TOOL_TRIGGERS.items():
        for p in patterns:
            try:
                if re.search(p, text_lower):
                    matched_tools.add(tool_name)
                    break
            except re.error:
                continue

    # Fallback to workflow triggers if no specific tool matched
    if not matched_tools:
        for tool_name, patterns in WORKFLOW_TRIGGERS.items():
            for p in patterns:
                try:
                    if re.search(p, text_lower):
                        target = extract_target(text_clean) or extract_url(text_clean)
                        if not target:
                            ips = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', text)
                            if ips:
                                target = ips[0]
                        if target:
                            return {
                                "tools": [{"name": "auto_workflow", "params": {"target": target}}],
                                "response": f"Menjalankan auto workflow untuk {target}...",
                                "reasoning": f"auto workflow {target}",
                            }
                        return {"tools": [], "response": "", "reasoning": "butuh target"}
                except re.error:
                    continue
        return {"tools": [], "response": "", "reasoning": "no match"}

    # Build tool params
    tools = []
    for tool_name in matched_tools:
        params = _build_tool_params(tool_name, text_clean, text_lower)
        if tool_name in ("generate_report", "show_context") or params:
            tools.append({"name": tool_name, "params": params})

    # Prioritaskan stego_analyze di atas file_search kalo ada path file spesifik
    has_stego = any(t["name"] == "stego_analyze" and t["params"].get("path") for t in tools)
    if has_stego:
        tools = [t for t in tools if t["name"] != "file_search"]

    return {"tools": tools, "response": "", "reasoning": f"matched: {', '.join(t['name'] for t in tools)}"}
