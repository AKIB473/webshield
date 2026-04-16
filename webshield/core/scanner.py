"""
Async Scanner Orchestrator — runs all modules in parallel (v1.1.0)
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
    # Core checks — fast
    "ssl_tls",
    "headers",
    "cookies",
    "cors",
    "csp",
    "clickjacking",
    "http_methods",
    # Content & config
    "info_leak",
    "sensitive_paths",
    "mixed_content",
    "sri_check",
    "security_txt",
    # Injection & logic
    "ssrf",
    "crlf_injection",
    "proto_pollution",
    # Intelligence
    "waf_detect",
    "tech_fingerprint",
    "secret_leak",
    "cloud_exposure",
    # Auth & session
    "jwt",
    "rate_limit",
    "open_redirect",
    # DNS & infra
    "dns_email",
    "subdomain_takeover",
    # Advanced
    "graphql",
    "request_smuggling",
    "supply_chain",
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


async def _run_module_async(mod_name: str, url: str, timeout: float,
                             progress, task_id) -> List[Finding]:
    loop = asyncio.get_event_loop()
    findings = await loop.run_in_executor(None, _run_module, mod_name, url, timeout)
    progress.advance(task_id)
    return findings


async def _run_all_async(url: str, modules: List[str],
                          timeout: float, verbose: bool) -> ScanResult:
    from .http import normalize_url
    url = normalize_url(url)
    result = ScanResult(target=url, score=100)
    start = time.time()

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
        tasks = [
            _run_module_async(m, url, timeout, progress, task)
            for m in modules
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    for mod_name, mod_findings in zip(modules, results):
        if isinstance(mod_findings, Exception):
            if verbose:
                console.print(f"[yellow]  ⚠ {mod_name}: {mod_findings}[/yellow]")
            continue
        for f in mod_findings:
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
        f"\n[bold cyan]🛡️  WebShield v1.1.0[/bold cyan] "
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
