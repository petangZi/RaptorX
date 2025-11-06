#!/usr/bin/env python3
import requests
import json
import os
import time
import re
import random
import string
import asyncio
from urllib.parse import urljoin, urlparse, quote
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich import print as rprint
from rich.panel import Panel
from rich.console import Console
from rich.traceback import install
from rich.prompt import Prompt, Confirm
from rich.table import Table
from concurrent.futures import ThreadPoolExecutor, as_completed

# 🚨 DISCLAIMER
DISCLAIMER = """
[bold red]⚠️ LEGAL WARNING ⚠️[/bold red]
Tools ini HANYA UNTUK:
- Lab legal (DVWA, PortSwigger Academy)
- Bug bounty berizin
- Internal pentest kantor
[bold yellow]JANGAN PAKE INI KE TARGET TANPA IZIN! GUE & LO BISA KENA UU ITE![/bold yellow]
"""

# 🧠 FINGERPRINTING ENGINE: DETEKSI FRAMEWORK & TEKNOLOGI
def fingerprint_target(target):
    """Deteksi teknologi dan framework dari header + response"""
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
    })
    
    try:
        resp = session.get(target, timeout=10, verify=False)
        headers = resp.headers
        text = resp.text.lower()
        
        tech = {
            "server": headers.get("Server", ""),
            "x-powered-by": headers.get("X-Powered-By", ""),
            "framework": "unknown",
            "cms": "unknown",
            "language": "unknown",
            "waf": "unknown"
        }
        
        # Deteksi framework/CMS
        if "moodle" in text or "moodle" in headers.get("Server", "").lower():
            tech["framework"] = "moodle"
            tech["cms"] = "moodle"
        elif "wordpress" in text or "wp-content" in text:
            tech["framework"] = "wordpress"
            tech["cms"] = "wordpress"
        elif "laravel" in text or "laravel" in headers.get("X-Powered-By", "").lower():
            tech["framework"] = "laravel"
            tech["language"] = "php"
        elif "django" in text or "csrf" in text:
            tech["framework"] = "django"
            tech["language"] = "python"
        elif "express" in headers.get("X-Powered-By", "").lower():
            tech["framework"] = "express"
            tech["language"] = "nodejs"
        elif "rails" in headers.get("X-Powered-By", "").lower() or "rails" in text:
            tech["framework"] = "rails"
            tech["language"] = "ruby"
        elif "nginx" in headers.get("Server", "").lower():
            tech["server"] = "nginx"
        elif "apache" in headers.get("Server", "").lower():
            tech["server"] = "apache"
        
        # WAF detection
        if "cloudflare" in headers.get("Server", "").lower() or "cloudflare" in text:
            tech["waf"] = "cloudflare"
        elif "sucuri" in text:
            tech["waf"] = "sucuri"
        elif "mod_security" in headers.get("Server", "").lower():
            tech["waf"] = "mod_security"
        
        return tech
    except:
        return {"server": "unknown", "framework": "unknown", "cms": "unknown", "language": "unknown", "waf": "unknown"}

# 🕵️‍♂️ TAHAP 1: ENUMERATION (FILTER & VALIDASI ENDPOINT)
def is_real_endpoint_enum(resp, baseline_404, url, target_tech):
    """Logika enum ketat: hanya 200/403 valid, sesuaikan teknologi"""
    if resp.status_code not in [200, 403]:
        return False
    
    if resp.status_code == 403:
        forbidden_keywords = ["forbidden", "access denied", "403", "permission denied"]
        if any(kw in resp.text.lower() for kw in forbidden_keywords):
            return False
    
    # Filter dynamic content
    resp_text = resp.text.lower()
    baseline_text = baseline_404["text"].lower() if baseline_404 else ""
    
    dynamic_patterns = [
        r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z',
        r'sessionid=[a-z0-9]{32}', 
        r'csrf_token=[a-z0-9]{64}',
        r'"timestamp":\s*\d+'
    ]
    for pattern in dynamic_patterns:
        resp_text = re.sub(pattern, '', resp_text)
        baseline_text = re.sub(pattern, '', baseline_text) if baseline_text else baseline_text
    
    # Hitung similarity
    if baseline_text and resp_text:
        similarity = len(set(resp_text) & set(baseline_text)) / len(set(resp_text))
        if similarity > 0.85:  # Jika mirip baseline 404
            return False
    
    # Keyword positif berdasarkan teknologi target
    positive_keywords = ["dashboard", "api", "user", "config", "data", "token", "auth"]
    
    # Tambah keyword spesifik teknologi
    if target_tech["framework"] == "moodle":
        positive_keywords.extend(["course", "mod", "assign", "quiz", "forum", "user", "admin"])
    elif target_tech["framework"] == "wordpress":
        positive_keywords.extend(["wp-admin", "wp-content", "wp-json", "admin"])
    elif target_tech["framework"] == "laravel":
        positive_keywords.extend(["_debugbar", "telescope", "horizon"])
    
    return any(kw in resp_text for kw in positive_keywords)

# 💣 TAHAP 2: EXPLOITATION (TEST PAYLOAD & VERIFIKASI ERROR)
def test_exploit_payload(url, payload, session):
    """Test payload dan cek apakah muncul error yang valid"""
    try:
        # Encode payload
        encoded_payload = quote(payload, safe='')
        if "?" in url:
            test_url = f"{url}&raptorx_exploit={encoded_payload}"
        else:
            test_url = f"{url}?raptorx_exploit={encoded_payload}"
        
        resp = session.get(test_url, timeout=8, verify=False)
        
        # Cari error patterns
        error_patterns = [
            r"Traceback.*most recent call last",
            r"Exception.*thread",
            r"Uncaught (TypeError|ReferenceError|SyntaxError)",
            r"PHP (Fatal error|Notice|Warning)",
            r"SQL syntax.*error",
            r"undefined offset",
            r"stack trace:",
            r"Cannot read property.*undefined",
            r"Error: ENOENT",
            r"Module not found",
            r"ImportError",
            r"NameError",
            r"AttributeError",
            r"KeyError",
            r"IndexError",
            r"ValueError",
            r"OSError",
            r"/etc/passwd",
            r"root:x:0:0",
            r"prototype pollution",
            r"__proto__",
            r"Cannot set property.*of undefined"
        ]
        
        for pattern in error_patterns:
            match = re.search(pattern, resp.text, re.IGNORECASE | re.DOTALL)
            if match:
                evidence = match.group(0)[:500]  # Ambil 500 char pertama
                return {
                    "success": True,
                    "evidence": evidence,
                    "response_status": resp.status_code,
                    "response_text": resp.text[:1000]
                }
        
        return {"success": False, "evidence": "", "response_status": resp.status_code}
    except:
        return {"success": False, "evidence": "", "response_status": 0}

# 🧠 RISK ASSESSMENT ENGINE v5
def assess_risk_v5(error_evidence, payload_used, target_tech):
    """Assessment berdasarkan evidence + payload + teknologi target"""
    evidence = error_evidence.lower()
    
    # Critical signals (bisa leak sensitive info)
    critical_signals = [
        ".env", "secret_key", "password", "database", "private_key", 
        "root:x", "aws_access", "api_key", "/etc/passwd", "/root/.ssh",
        "config.php", "database.yml", "secrets.json", "credentials"
    ]
    
    # High signals (error disclosure)
    high_signals = [
        "stack trace", "traceback", "exception", "fatal error", "uncaught",
        "sql syntax", "undefined offset", "call to undefined",
        "file not found", "permission denied", "connection refused"
    ]
    
    # Medium signals
    medium_signals = [
        "warning", "notice", "deprecated", "failed to open stream",
        "undefined variable", "array to string conversion"
    ]
    
    # Cek berdasarkan payload category
    payload_category = "unknown"
    if "__proto__" in payload_used.lower() or "prototype" in payload_used.lower():
        payload_category = "prototype_pollution"
    elif ".env" in payload_used or "/etc/passwd" in payload_used:
        payload_category = "file_inclusion"
    elif "or 1=1" in payload_used.lower() or "union select" in payload_used.lower():
        payload_category = "sql_injection"
    elif "<script>" in payload_used or "alert(" in payload_used.lower():
        payload_category = "xss"
    
    # Hitung risk berdasarkan evidence
    critical_score = sum(1 for sig in critical_signals if sig in evidence)
    high_score = sum(1 for sig in high_signals if sig in evidence)
    medium_score = sum(1 for sig in medium_signals if sig in evidence)
    
    # Adjust risk berdasarkan payload category
    if payload_category == "file_inclusion" and critical_score > 0:
        return "critical", 95
    elif payload_category == "prototype_pollution" and high_score > 0:
        return "critical", 90
    elif critical_score > 0:
        return "critical", 85
    elif high_score > 0:
        return "high", 75
    elif medium_score > 0:
        return "medium", 50
    else:
        return "low", 25

# 🛠️ AUTO-GENERATE CURL EXPLOIT
def generate_curl_command_v5(url, payload=None):
    """Bikin curl command siap jalan"""
    base_cmd = f"curl -s -i -X GET '{url}'"
    headers = [
        "-H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36'",
        "-H 'Accept: */*'",
        "-H 'Connection: close'"
    ]
    
    if payload:
        encoded_payload = quote(payload, safe='')
        if "?" in url:
            exploit_url = f"{url}&raptorx_exploit={encoded_payload}"
        else:
            exploit_url = f"{url}?raptorx_exploit={encoded_payload}"
        base_cmd = base_cmd.replace(url, exploit_url)
    
    return base_cmd + " " + " ".join(headers)

# 🕵️‍♂️ CORE ENGINE v5: TIGA TAHAPAN
class RaptorXProtocol:
    def __init__(self, target, wordlist="wordlist.txt", payloads="payloads.json", concurrency=5):
        self.target = target.rstrip('/')
        self.concurrency = concurrency
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
            "Accept": "*/*",
            "Connection": "close"
        })
        self.console = Console()
        self.results = {
            "target": target,
            "scan_start": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "target_tech": {},
            "endpoints": [],
            "exploits": [],
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "total_requests": 0
        }
        
        # Load resources
        self.load_wordlist(wordlist)
        self.load_payloads(payloads)
        self.get_baseline_404()
        self.fingerprint_target()
    
    def load_wordlist(self, path):
        """Load wordlist dengan filter ketat"""
        if not os.path.exists(path):
            rprint(f"[bold red]❌ Wordlist {path} ga ketemu! Bikin dulu bro![/bold red]")
            exit(1)
        
        with open(path) as f:
            raw_endpoints = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        
        static_exts = {".css", ".js", ".jpg", ".jpeg", ".png", ".gif", ".woff", ".ttf", ".svg", ".pdf", ".zip", ".tar", ".gz", ".ico"}
        seen = set()
        self.endpoints = []
        for ep in raw_endpoints:
            if any(ep.endswith(ext) for ext in static_exts) or "/static/" in ep or ep in seen:
                continue
            seen.add(ep)
            self.endpoints.append(ep)
        
        rprint(f"[cyan]✅ Loaded {len(self.endpoints)} UNIQUE endpoints[/cyan]")
    
    def load_payloads(self, path):
        """Load payloads valid JSON"""
        if not os.path.exists(path):
            rprint(f"[bold red]❌ Payloads file {path} ga ketemu! Bikin dulu bro![/bold red]")
            exit(1)
        
        try:
            with open(path) as f:
                self.payloads_data = json.load(f)
        except json.JSONDecodeError as e:
            rprint(f"[bold red]❌ ERROR: payloads.json RUSAK! Perbaiki dulu: {str(e)}[/bold red]")
            exit(1)
        
        self.payloads = []
        for category in ["js_breakers", "error_triggers", "prototype_pollution", "file_inclusion", "sql_injection"]:
            if category in self.payloads_data:  # ✅ FIX: GANTI self.payloads_ JADI self.payloads_data
                for payload in self.payloads_data[category]:
                    self.payloads.append({
                        "payload": payload,
                        "category": category
                    })
        rprint(f"[magenta]💣 Loaded {len(self.payloads)} exploit payloads[/magenta]")
    
    def get_baseline_404(self):
        """Ambil baseline 404"""
        random_str = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
        test_urls = [
            f"/{random_str}.php",
            f"/{random_str}/",
            f"/{random_str}?q={random_str}"
        ]
        
        baseline_responses = []
        for url in test_urls:
            try:
                resp = self.session.get(urljoin(self.target, url), timeout=5, verify=False)
                baseline_responses.append({
                    "status": resp.status_code,
                    "length": len(resp.text),
                    "text": resp.text[:500]
                })
            except:
                continue
        
        if baseline_responses:
            self.baseline_404 = max(baseline_responses, key=lambda x: x["length"])
            rprint(f"[green]🎯 Baseline 404: {self.baseline_404['status']} | {self.baseline_404['length']} bytes[/green]")
        else:
            self.baseline_404 = {"status": 404, "length": 0, "text": ""}
            rprint("[yellow]⚠️ Gagal baseline 404 - pake default[/yellow]")
    
    def fingerprint_target(self):
        """Fingerprint teknologi target"""
        rprint("[blue]🔍 Fingerprinting target...[/blue]")
        self.results["target_tech"] = fingerprint_target(self.target)
        tech = self.results["target_tech"]
        rprint(f"[green]✅ Framework: {tech['framework']} | CMS: {tech['cms']} | Language: {tech['language']}[/green]")
    
    def scan_endpoint(self, endpoint):
        """Tahap 1: Enumeration - Cari endpoint valid"""
        url = urljoin(self.target, endpoint)
        result = {
            "url": url,
            "status": 0,
            "is_real": False,
            "content_type": "",
            "vulnerabilities": [],
            "exploits_found": []
        }
        
        try:
            resp = self.session.get(url, timeout=8, verify=False)
            self.results["total_requests"] += 1
            
            result["status"] = resp.status_code
            result["content_type"] = resp.headers.get("Content-Type", "")
            
            # Tahap 1: Validasi endpoint real
            result["is_real"] = is_real_endpoint_enum(resp, self.baseline_404, url, self.results["target_tech"])
            
            if result["is_real"]:
                # Simpan endpoint accessible
                self.results["exploits"].append({
                    "type": "accessible",
                    "url": url,
                    "status": result["status"],
                    "curl": generate_curl_command_v5(url)
                })
                
                # Tahap 2: Cek kalo endpoint sensitif, test exploit
                sensitive_indicators = [".json", "api", "debug", "config", "backup", "course", "mod", "user", "login", "admin"]
                if any(ind in endpoint.lower() for ind in sensitive_indicators):
                    for payload_info in self.payloads:
                        payload = payload_info["payload"]
                        category = payload_info["category"]
                        
                        # Test exploit payload
                        exploit_result = test_exploit_payload(url, payload, self.session)
                        self.results["total_requests"] += 1
                        
                        if exploit_result["success"]:
                            # Tahap 3: Assess risk
                            risk_level, confidence = assess_risk_v5(
                                exploit_result["evidence"], 
                                payload, 
                                self.results["target_tech"]
                            )
                            
                            if risk_level in ["critical", "high", "medium"]:
                                curl_cmd = generate_curl_command_v5(url, payload)
                                
                                vuln = {
                                    "payload_used": payload,
                                    "category": category,
                                    "test_url": url,
                                    "evidence": exploit_result["evidence"],
                                    "risk_level": risk_level,
                                    "confidence": confidence,
                                    "curl_cmd": curl_cmd
                                }
                                result["vulnerabilities"].append(vuln)
                                
                                # Simpan ke global exploits
                                self.results["exploits"].append({
                                    "type": "exploitable",
                                    "risk_level": risk_level,
                                    "url": url,
                                    "payload": payload,
                                    "evidence": exploit_result["evidence"],
                                    "curl": curl_cmd,
                                    "confidence": confidence
                                })
                                
                                if risk_level == "critical":
                                    self.results["critical_count"] += 1
                                elif risk_level == "high":
                                    self.results["high_count"] += 1
                                elif risk_level == "medium":
                                    self.results["medium_count"] += 1
        
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    def run(self):
        """Jalankan 3 tahapan: Enum → Exploit → Verify"""
        rprint(Panel(f"[bold green]{DISCLAIMER}[/bold green]", title="🚨 LEGAL DISCLAIMER 🚨"))
        rprint(f"\n[bold cyan]🚀 Starting RAPTORX PROTOCOL on [yellow]{self.target}[/yellow][/bold cyan]")
        rprint(f"[bold magenta]⚡ Concurrency: {self.concurrency} threads[/bold magenta]\n")
        
        start_time = time.time()
        
        # Tahap 1: Enumerate endpoints
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=None),
            TextColumn("[bold green]{task.percentage:>3.0f}%[/bold green]"),
            console=self.console
        ) as progress:
            task = progress.add_task("[cyan]Tahap 1: Enumerating endpoints...", total=len(self.endpoints))
            
            with ThreadPoolExecutor(max_workers=self.concurrency) as executor:
                futures = {executor.submit(self.scan_endpoint, ep): ep for ep in self.endpoints}
                
                for future in as_completed(futures):
                    result = future.result()
                    self.results["endpoints"].append(result)
                    progress.advance(task)
                # Simpan hasil
        self.results["scan_end"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        self.results["scan_duration"] = f"{time.time() - start_time:.2f}s"
        
        # Generate filename
        domain = urlparse(self.target).netloc.replace(":", "_").replace(".", "_")
        timestamp = int(time.time())
        output_dir = "output"
        os.makedirs(output_dir, exist_ok=True)
        output_file = f"{output_dir}/raptorx_{domain}_{timestamp}.json"
        
        with open(output_file, "w") as f:
            json.dump(self.results, f, indent=2)
        
        # Tampilkan summary
        self.show_summary(output_file)
    
    def show_summary(self, output_file):
        """Tampilkan hasil 3 tahapan: Enum → Exploit → Verify"""
        total_real = sum(1 for ep in self.results["endpoints"] if ep.get("is_real"))
        total_vulns = sum(len(ep["vulnerabilities"]) for ep in self.results["endpoints"])
        
        # Summary utama
        summary = f"""
🔥 [bold white]RAPTORX PROTOCOL COMPLETE! 🔥
🎯 Target: [yellow]{self.results['target']}[/yellow]
⏱️ Duration: [cyan]{self.results['scan_duration']}[/cyan]
📡 Total Requests: [magenta]{self.results['total_requests']}[/magenta]

✅ [bold]TAHAP 1: ENUMERATION[/bold]
   Real Endpoints Found: [green]{total_real}[/green]
   Framework: [blue]{self.results['target_tech']['framework']}[/blue]

💣 [bold]TAHAP 2: EXPLOITATION & VERIFICATION[/bold]
   Total Vulnerabilities: [red]{total_vulns}[/red]
   - Critical: [bold red]{self.results['critical_count']}[/bold red]
   - High: [bold yellow]{self.results['high_count']}[/bold yellow]
   - Medium: [bold blue]{self.results['medium_count']}[/bold blue]

💾 Results: [bold green]{output_file}[/bold green]
"""
        rprint(Panel(summary, title="[bold red]RAPTORX PROTOCOL SUMMARY[/bold red]", border_style="bold yellow"))
        
        # Tampilkan exploitable endpoints
        exploitable = [exp for exp in self.results["exploits"] if exp["type"] == "exploitable"]
        if exploitable:
            table = Table(title="[bold red]🚨 VERIFIED EXPLOITABLE VULNERABILITIES 🚨[/bold red]", show_lines=True)
            table.add_column("Risk", style="bold", width=10)
            table.add_column("Confidence", style="cyan", width=12)
            table.add_column("Endpoint", style="yellow", overflow="fold")
            table.add_column("Payload", style="magenta", overflow="fold")
            table.add_column("Curl Command", style="green", overflow="fold")
            
            for exp in exploitable:
                risk_style = "bold red" if exp["risk_level"] == "critical" else ("bold yellow" if exp["risk_level"] == "high" else "bold blue")
                table.add_row(
                    f"[{risk_style}]{exp['risk_level'].upper()}[/{risk_style}]",
                    f"[cyan]{exp['confidence']}%[/cyan]",
                    exp["url"],
                    exp["payload"][:50] + "..." if len(exp["payload"]) > 50 else exp["payload"],
                    exp["curl"]
                )
            
            self.console.print(table)
        
        # Tampilkan accessible endpoints
        accessible = [exp for exp in self.results["exploits"] if exp["type"] == "accessible"]
        if accessible:
            self.console.print(f"\n[bold blue]🚪 {len(accessible)} ACCESSIBLE ENDPOINTS (200/403):[/bold blue]")
            for i, ep in enumerate(accessible[:10], 1):  # Tampilkan 10 aja biar rapi
                self.console.print(f"[cyan]{i}. {ep['url']}[/cyan] → Status: [green]{ep['status']}[/green]")
            if len(accessible) > 10:
                self.console.print(f"[italic yellow]+ {len(accessible)-10} more endpoints...[/italic yellow]")
        
        # Conclusion
        conclusion = f"""
[bold green]✅ CONCLUSION:[/bold green]
1. [bold]Critical findings ({self.results['critical_count']})[/bold]: Segera verifikasi manual — bisa leak sensitive info
2. [bold]High findings ({self.results['high_count']})[/bold]: Error disclosure yang bisa dimanfaatkan
3. [bold]Total exploitable ({total_vulns})[/bold]: Sudah terverifikasi bisa di-exploit
4. [bold]Recommendation[/bold]: Gunakan curl command dari tabel untuk verifikasi manual

[blink bold red]JANGAN LUPA MAKAN & MINUM AIR PUTIH![/blink bold red] 💧
"""
        self.console.print(Panel(conclusion, title="🎯 FINAL CONCLUSION", border_style="green"))

# 🚀 MAIN EXECUTION
if __name__ == "__main__":
    install(show_locals=False)
    
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    console = Console()
    
    rprint(Panel(
        "[bold magenta]🦖 RAPTORX PROTOCOL v5.1 — ENUM → EXPLOIT → VERIFY[/bold magenta]\n"
        "[bold yellow]TIDAK ASAL KIRIM REQUEST! LOGIKA KERAS! VERIFIKASI LENGKAP![/bold yellow]",
        title="🔥 RAPTORX PROTOCOL LAUNCH 🔥",
        border_style="bold cyan"
    ))
    
    target = Prompt.ask(
        "[bold green]🎯 Enter target URL[/bold green]",
        default="http://localhost"
    )
    
    wordlist = Prompt.ask(
        "[bold cyan]📁 Path to wordlist.txt[/bold cyan]",
        default="wordlist.txt"
    )
    
    payloads = Prompt.ask(
        "[bold magenta]💣 Path to payloads.json[/bold magenta]",
        default="payloads.json"
    )
    
    concurrency = int(Prompt.ask(
        "[bold yellow]⚡ Concurrency threads (default: 5)[/bold yellow]",
        default="5"
    ))
    
    if not Confirm.ask(f"[bold red]🚨 Start RAPTORX PROTOCOL on [yellow]{target}[/yellow] with {concurrency} threads?[/bold red]"):
        rprint("[bold green]✅ Protocol canceled. Stay safe bro![/bold green]")
        exit(0)
    
    raptor = RaptorXProtocol(
        target=target,
        wordlist=wordlist,
        payloads=payloads,
        concurrency=concurrency
    )
    raptor.run()
    
    rprint("\n[bold green]✅ RAPTORX PROTOCOL SELESAI! SEMUA VULN TERVERIFIKASI — TIDAK ADA LAGI FALSE POSITIVE![/bold green]")
    rprint("[italic yellow]DM gue di Discord: Redzskid#1337 — GUE BANTU SAMPE LO PAHAM![/italic yellow]")
