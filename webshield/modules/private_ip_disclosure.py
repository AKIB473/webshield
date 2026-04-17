"""Private IP Disclosure Module (v1.8.0) — ZAP rule 2"""
from __future__ import annotations
import re
from typing import List
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

PRIVATE_IP = re.compile(
    r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
    r'172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|'
    r'192\.168\.\d{1,3}\.\d{1,3}|'
    r'127\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
    r'169\.254\.\d{1,3}\.\d{1,3}|'
    r'::1|fc00::[a-f0-9:]+|fd[a-f0-9]{2}:[a-f0-9:]+)\b',
    re.I
)
SKIP_CONTEXT = re.compile(r'example|test|placeholder|192\.168\.1\.(1|100|0)', re.I)

def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    with get_client(timeout=min(timeout, 8.0)) as client:
        try:
            resp = client.get(url)
            # Check response body AND headers
            sources = [("response body", resp.text[:50000]), ("response headers", str(dict(resp.headers)))]
            for (src, text) in sources:
                matches = list(set(PRIVATE_IP.findall(text)))
                real_matches = [m for m in matches if not SKIP_CONTEXT.search(m)]
                if real_matches:
                    findings.append(Finding(
                        title=f"Private IP Address Disclosed in {src.title()}",
                        severity=Severity.LOW,
                        description=(
                            f"Private/internal IP addresses were found in the {src}: {real_matches[:3]}. "
                            "Internal IPs help attackers map the network topology and identify targets "
                            "for further lateral movement attacks."
                        ),
                        evidence=f"URL: {url}\nInternal IPs: {real_matches[:5]}\nSource: {src}",
                        remediation=(
                            "Remove internal IP references from all public-facing responses. "
                            "Configure reverse proxies to strip internal headers (X-Real-IP, X-Forwarded-For)."
                        ),
                        code_fix=(
                            "# Nginx — strip internal headers before proxying:\n"
                            "proxy_set_header X-Real-IP '';\n"
                            "proxy_hide_header X-Backend-Server;\n"
                            "proxy_hide_header X-Powered-By;"
                        ),
                        reference="https://owasp.org/www-project-web-security-testing-guide/",
                        module="private_ip_disclosure",
                        cvss=3.1,
                    ))
                    break
        except Exception:
            pass
    return findings
