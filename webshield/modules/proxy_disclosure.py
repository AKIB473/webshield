"""Proxy & Infrastructure Disclosure Module (v1.8.0) — ZAP rule 40025"""
from __future__ import annotations
import re
from typing import List
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

PROXY_HEADERS = [
    "Via", "X-Via", "X-Forwarded-By", "X-Forwarded-Server",
    "X-Backend-Server", "X-Origin-Server", "X-Upstream",
    "X-Proxy-ID", "X-Varnish", "X-Cache", "X-Cache-Hits",
    "CF-Cache-Status", "X-Drupal-Cache", "X-Squid-Error",
    "Forwarded", "X-Azure-Ref", "X-ARR-LOG-ID",
]
INTERNAL_IP = re.compile(r'10\.\d+\.\d+\.\d+|172\.(1[6-9]|2[0-9]|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+')
VERSION_LEAK = re.compile(r'nginx/[\d.]+|Apache/[\d.]+|varnish/[\d.]+|squid/[\d.]+|haproxy[\d./]+', re.I)

def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    with get_client(timeout=min(timeout, 8.0)) as client:
        try:
            resp = client.get(url)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            all_header_str = str(dict(resp.headers))

            # Check proxy-revealing headers
            proxy_found = []
            for h in PROXY_HEADERS:
                v = headers.get(h.lower(), "")
                if v:
                    proxy_found.append(f"{h}: {v}")
                    # Check for internal IPs
                    if INTERNAL_IP.search(v):
                        findings.append(Finding(
                            title=f"Internal IP Disclosed via {h} Header",
                            severity=Severity.MEDIUM,
                            description=f"The {h} header reveals internal infrastructure IP addresses.",
                            evidence=f"{h}: {v}",
                            remediation=f"Strip the {h} header at the edge/CDN before returning to clients.",
                            code_fix=f"# Nginx:\nproxy_hide_header {h};",
                            reference="https://owasp.org/www-project-web-security-testing-guide/",
                            module="proxy_disclosure",
                            cvss=4.3,
                        ))

            # Check version disclosure in Server/Via headers
            server = headers.get("server", "") + headers.get("via", "")
            v_match = VERSION_LEAK.search(server + all_header_str)
            if v_match:
                findings.append(Finding(
                    title=f"Infrastructure Version Disclosed ({v_match.group(0)})",
                    severity=Severity.LOW,
                    description=f"Server version '{v_match.group(0)}' is disclosed in response headers. Attackers use this to target version-specific CVEs.",
                    evidence=f"Header value: {v_match.group(0)}",
                    remediation="Configure your web server to suppress version information.",
                    code_fix=(
                        "# Nginx:\nserver_tokens off;\n\n"
                        "# Apache:\nServerTokens Prod\nServerSignature Off"
                    ),
                    reference="https://owasp.org/www-project-web-security-testing-guide/",
                    module="proxy_disclosure",
                    cvss=3.1,
                ))
        except Exception:
            pass
    return findings
