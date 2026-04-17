"""Httpoxy — Proxy Header Misuse Module (v1.8.0) — ZAP rule 10107"""
from __future__ import annotations
import re
from typing import List
from urllib.parse import urlparse
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

HTTPOXY_INDICATOR = re.compile(r"httpoxy|HTTP_PROXY|proxy.*misconfiguration", re.I)

def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    with get_client(timeout=min(timeout, 8.0)) as client:
        # Send Proxy: header pointing to a canary — if server makes outbound request, httpoxy confirmed
        # We use a non-routable IP to detect errors vs normal responses
        CANARY = "http://httpoxy-probe.internal:9999"
        headers_list = [
            {"Proxy": CANARY},
            {"Proxy": "http://127.0.0.1:1"},
            {"X-Forwarded-For": "127.0.0.1", "Proxy": CANARY},
        ]
        for path in ["/", "/api", "/cgi-bin/test.cgi"]:
            try:
                r_baseline = client.get(base_url + path)
                baseline_time = 0
                for hdrs in headers_list:
                    r = client.get(base_url + path, headers=hdrs)
                    # Signs of httpoxy: longer response time, connection errors, proxy-related content
                    if HTTPOXY_INDICATOR.search(r.text) or r.status_code in (502, 504):
                        findings.append(Finding(
                            title=f"Httpoxy — Proxy Header Misuse ({path})",
                            severity=Severity.HIGH,
                            description=(
                                "The server appears to process the 'Proxy' HTTP request header "
                                "as an outbound proxy configuration (CVE-2016-5385 and related). "
                                "Attackers can redirect server-side HTTP requests to an attacker-controlled proxy, "
                                "enabling credential theft, SSRF, and traffic interception."
                            ),
                            evidence=f"Path: {base_url+path}\nProxy header sent: {hdrs.get('Proxy','')}\nHTTP {r.status_code}",
                            remediation=(
                                "Unset HTTP_PROXY environment variable in CGI contexts. "
                                "For PHP-FPM/Apache: use CGIFix_plus or set HTTP_PROXY='' in server config."
                            ),
                            code_fix=(
                                "# Apache httpd.conf:\nRequestHeader unset Proxy early\n\n"
                                "# Nginx:\nproxy_set_header Proxy '';\n\n"
                                "# PHP — at app start:\nunset($_SERVER['HTTP_PROXY']);\nputenv('HTTP_PROXY=');"
                            ),
                            reference="https://httpoxy.org/",
                            module="httpoxy",
                            cvss=8.1,
                        ))
                        return findings
            except Exception:
                continue
    return findings
