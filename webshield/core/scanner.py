"""
Async Scanner Orchestrator — runs all modules in parallel (v1.6.0)
Includes lightweight crawling to discover URLs with params for injection modules.
"""

from __future__ import annotations
import time
import asyncio
import importlib
from typing import List, Optional
from rich.console import Console
from rich.progress import (
    Progress, SpinnerColumn, TextColumn,
    BarColumn, TaskProgressColumn, TimeElapsedColumn,
)

from .models import ScanResult, Finding

console = Console()

ALL_MODULES = [
    # Core security headers & config
    "ssl_tls",
    "headers",
    "cookies",
    "cors",
    "csp",
    "clickjacking",
    "http_methods",
    # Content & disclosure
    "info_leak",
    "sensitive_paths",
    "mixed_content",
    "sri_check",
    "security_txt",
    "broken_links",
    # Injection attacks
    "sql_injection",
    "xss_detection",
    "lfi",
    "xxe",
    "ssrf",
    "crlf_injection",
    "proto_pollution",
    # Malware & compromise
    "malware_indicators",
    "log4shell",
    # Intelligence
    "waf_detect",
    "tech_fingerprint",
    "secret_leak",
    "cloud_exposure",
    # Auth & session
    "jwt",
    "csrf_check",
    "rate_limit",
    "open_redirect",
    # DNS & infra
    "dns_email",
    "subdomain_takeover",
    # Advanced
    "graphql",
    "request_smuggling",
    "supply_chain",
    # Access control & API security (v1.3.0)
    "idor_check",
    "api_exposure",
    "dir_listing",
    "auth_hardening",
    # Advanced injection & protocol attacks (v1.5.0)
    "cmd_injection",
    "nosql_injection",
    "http_header_injection",
    "insecure_deserialization",
    # Deep attack surface (v1.5.0)
    "ssti",
    "web_cache_deception",
    "file_upload",
    "dom_xss",
    "business_logic",
    # Nikto/ZAP parity + CVE coverage (v1.6.0)
    "source_code_disclosure",
    "bypass_403",
    "pii_detection",
    "spring_actuator",
    "http_parameter_pollution",
    "cve_checks",
    "websocket_security",
]

MODULE_LABELS = {
    "ssl_tls":            "SSL/TLS Certificate & Protocols",
    "headers":            "HTTP Security Headers",
    "cookies":            "Cookie Security Flags",
    "cors":               "CORS Misconfiguration",
    "csp":                "Content Security Policy",
    "clickjacking":       "Clickjacking Protection",
    "http_methods":       "Dangerous HTTP Methods",
    "info_leak":          "Information Leakage (.env, .git, backups)",
    "sensitive_paths":    "Sensitive Path Exposure",
    "mixed_content":      "Mixed Content Detection",
    "sri_check":          "Subresource Integrity (SRI)",
    "security_txt":       "security.txt (RFC 9116)",
    "ssrf":               "Server-Side Request Forgery (SSRF)",
    "crlf_injection":     "CRLF / HTTP Response Splitting",
    "proto_pollution":    "JavaScript Prototype Pollution",
    "waf_detect":         "WAF Detection",
    "tech_fingerprint":   "Technology & CVE Fingerprinting",
    "secret_leak":        "Secret & Credential Leak Detection",
    "cloud_exposure":     "Cloud Storage & Infrastructure Exposure",
    "jwt":                "JWT Token Analysis",
    "rate_limit":         "Rate Limiting / Brute Force Protection",
    "open_redirect":      "Open Redirect",
    "dns_email":          "DNS / SPF / DKIM / DMARC",
    "subdomain_takeover": "Subdomain Takeover",
    "graphql":            "GraphQL Security",
    "request_smuggling":  "HTTP Request Smuggling",
    "supply_chain":       "Supply Chain / Dependency CVEs",
    # v1.2.0
    "sql_injection":      "SQL Injection (Error-based)",
    "xss_detection":      "XSS — Reflected Cross-Site Scripting",
    "lfi":                "Local File Inclusion / Path Traversal",
    "xxe":                "XXE — XML External Entity Injection",
    "malware_indicators": "Malware & Compromise Indicators",
    "log4shell":          "Log4Shell / Shellshock / Critical CVEs",
    "csrf_check":         "CSRF — Cross-Site Request Forgery",
    "broken_links":       "Broken Links & Dead Asset Detection",
    # v1.3.0
    "idor_check":             "IDOR / Broken Access Control (OWASP A01:2025)",
    "api_exposure":           "API Endpoint & OpenAPI/GraphQL Exposure",
    "dir_listing":            "Directory Listing Detection",
    "auth_hardening":         "Authentication Hardening (MFA, Rate Limit, Default Creds)",
    # v1.5.0
    "cmd_injection":          "OS Command Injection (RCE)",
    "nosql_injection":        "NoSQL Injection (MongoDB Auth Bypass)",
    "http_header_injection":  "Host Header Injection / Cache Poisoning",
    "insecure_deserialization": "Insecure Deserialization (Java/PHP/.NET)",
    # v1.5.0
    "ssti":                   "Server-Side Template Injection (RCE via Jinja2/Twig/FreeMarker)",
    "web_cache_deception":    "Web Cache Deception & Cache Poisoning",
    "file_upload":            "File Upload Security & Webshell Detection",
    "dom_xss":                "DOM-Based XSS (JavaScript Source-to-Sink Analysis)",
    "business_logic":         "Business Logic Flaws (Enumeration, Mass Assignment, Workflow)",
    # v1.6.0
    "source_code_disclosure":     "Source Code Disclosure (.git, .svn, backups, source maps)",
    "bypass_403":                 "403 Bypass (Verb Tampering, URL Manipulation, Header Injection)",
    "pii_detection":              "PII Detection (SSN, Credit Cards, Email Dumps, IBAN)",
    "spring_actuator":            "Spring Boot Actuator & Framework Debug Panel Exposure",
    "http_parameter_pollution":   "HTTP Parameter Pollution (HPP — WAF Bypass, Business Logic)",
    "cve_checks":                 "CVE Fingerprinting (Text4Shell, Confluence, Exchange, Grafana, Struts...)",
    "websocket_security":         "WebSocket Security (CSWSH, Origin Validation, ws:// Downgrade)",
}


def _run_module(mod_name: str, url: str, timeout: float) -> List[Finding]:
    try:
        mod = importlib.import_module(f"webshield.modules.{mod_name}")
        findings: List[Finding] = mod.scan(url, timeout=timeout)
        for f in findings:
            f.module = mod_name
        return findings
    except ModuleNotFoundError:
        return []
    except Exception as e:
        from .models import Severity
        return [Finding(
            title=f"Module error: {mod_name}",
            severity=Severity.INFO,
            description=str(e),
            module=mod_name,
        )]


# Per-module hard timeout: even if a module's HTTP calls don't respect timeout,
# we cancel the whole module coroutine after this many seconds.
MODULE_HARD_TIMEOUT = 45.0  # seconds


async def _run_module_async(mod_name: str, url: str, timeout: float,
                             progress, task_id) -> List[Finding]:
    loop = asyncio.get_event_loop()
    try:
        findings = await asyncio.wait_for(
            loop.run_in_executor(None, _run_module, mod_name, url, timeout),
            timeout=MODULE_HARD_TIMEOUT,
        )
    except asyncio.TimeoutError:
        findings = []
        from .models import Severity
        findings = [Finding(
            title=f"Module timed out: {mod_name}",
            severity=Severity.INFO,
            description=f"Module '{mod_name}' exceeded the hard timeout ({MODULE_HARD_TIMEOUT}s) and was cancelled.",
            module=mod_name,
        )]
    progress.advance(task_id)
    return findings


# Modules that benefit from URL params — run against crawled URLs too
PARAM_HUNGRY_MODULES = {
    "sql_injection", "xss_detection", "ssti", "cmd_injection",
    "lfi", "ssrf", "open_redirect", "proto_pollution",
    "crlf_injection", "log4shell",
}


def _crawl_for_params(url: str, timeout: float) -> List[str]:
    """Run crawler and return discovered URLs with params."""
    try:
        from .crawler import crawl
        urls_with_params, _ = crawl(url, timeout=min(timeout, 8.0), max_pages=20)
        return urls_with_params
    except Exception:
        return []


async def _run_all_async(url: str, modules: List[str],
                          timeout: float, verbose: bool) -> ScanResult:
    from .http import normalize_url
    url = normalize_url(url)
    result = ScanResult(target=url, score=100)
    start = time.time()

    # Phase 1: Crawl for param-bearing URLs (feeds injection modules)
    # Must complete BEFORE module scanning starts
    loop = asyncio.get_event_loop()
    crawled_urls: List[str] = []
    param_modules_active = [m for m in modules if m in PARAM_HUNGRY_MODULES]

    if param_modules_active:
        console.print("[dim]🔍 Crawling for injectable parameters...[/dim]")
        try:
            crawled_urls = await asyncio.wait_for(
                loop.run_in_executor(None, _crawl_for_params, url, min(timeout, 10.0)),
                timeout=18.0,
            )
        except (asyncio.TimeoutError, Exception):
            crawled_urls = []
        n = len(crawled_urls)
        console.print(f"[dim]🔍 Found {n} URL(s) with parameters — running injection modules[/dim]")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=28),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task(
            f"[cyan]Scanning {url}[/cyan]",
            total=len(modules),
        )

        async def run_one(mod_name: str) -> List[Finding]:
            # http_header_injection probes no-param paths — use interesting_paths
            if mod_name == "http_header_injection":
                from urllib.parse import urlparse as _up2
                base2 = f"{_up2(url).scheme}://{_up2(url).netloc}"
                loop3 = asyncio.get_event_loop()
                for test_url in [url, base2 + "/host-reflect"] + \
                                 [base2 + p for p in ["/", "/app", "/home", "/dashboard"]]:
                    try:
                        r = await asyncio.wait_for(
                            loop3.run_in_executor(None, _run_module, mod_name, test_url, timeout),
                            timeout=MODULE_HARD_TIMEOUT,
                        )
                    except asyncio.TimeoutError:
                        r = []
                    real = [f for f in r if f.severity.value not in ("INFO",) and "timed out" not in f.title]
                    if real:
                        progress.advance(task)
                        return r
                progress.advance(task)
                return []

            # For param-hungry modules, try ALL crawled URLs + base URL
            if mod_name in PARAM_HUNGRY_MODULES and crawled_urls:
                all_findings: List[Finding] = []
                loop2 = asyncio.get_event_loop()
                # Try every crawled URL; stop on first real finding
                for test_url in crawled_urls + [url]:
                    try:
                        mfindings = await asyncio.wait_for(
                            loop2.run_in_executor(None, _run_module, mod_name, test_url, timeout),
                            timeout=MODULE_HARD_TIMEOUT,
                        )
                    except asyncio.TimeoutError:
                        mfindings = []
                    real = [f for f in mfindings
                            if "timed out" not in f.title and f.severity.value != "INFO"]
                    if real:
                        all_findings = mfindings
                        break
                    if mfindings and not all_findings:
                        all_findings = mfindings  # keep INFO as fallback
                progress.advance(task)
                return all_findings
            else:
                return await _run_module_async(mod_name, url, timeout, progress, task)

        tasks_coros = [run_one(m) for m in modules]
        results = await asyncio.gather(*tasks_coros, return_exceptions=True)

    seen_titles: set = set()
    for mod_name, mod_findings in zip(modules, results):
        if isinstance(mod_findings, Exception):
            if verbose:
                console.print(f"[yellow]  ⚠ {mod_name}: {mod_findings}[/yellow]")
            continue
        for f in mod_findings:
            # Deduplicate by title (same finding from different URLs)
            if f.title not in seen_titles:
                seen_titles.add(f.title)
                result.add_finding(f)
        result.modules_run.append(mod_name)

    result.scan_duration = round(time.time() - start, 2)
    return result


def run_scan(
    target: str,
    modules: Optional[List[str]] = None,
    timeout: float = 10.0,
    verbose: bool = False,
) -> ScanResult:
    from .http import normalize_url
    url = normalize_url(target)
    modules_to_run = modules or ALL_MODULES

    console.print(
        f"\n[bold cyan]🛡️  WebShield v1.6.0[/bold cyan] "
        f"scanning [bold]{url}[/bold]\n"
    )

    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    return loop.run_until_complete(
        _run_all_async(url, modules_to_run, timeout, verbose)
    )
