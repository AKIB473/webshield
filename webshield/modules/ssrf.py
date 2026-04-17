"""
SSRF (Server-Side Request Forgery) Detection Module
Tests URL parameters for SSRF via cloud metadata endpoints and internal addresses.
Learned from: GSEC (ssrf.py — best SSRF logic), Greaper (ssrf.py), wshawk
"""

from __future__ import annotations
import re
from typing import List
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

# Parameters commonly used for URL fetching
SSRF_PARAMS = [
    "url", "uri", "path", "src", "source", "dest", "destination",
    "target", "fetch", "load", "link", "host", "site", "page",
    "feed", "proxy", "callback", "image", "img", "file", "resource",
    "redirect", "return", "open", "api", "endpoint", "data",
]

# Payloads to test SSRF — ordered by severity
SSRF_PROBES = [
    # Cloud metadata — most impactful
    ("http://169.254.169.254/latest/meta-data/",         "AWS EC2 metadata endpoint"),
    ("http://metadata.google.internal/computeMetadata/v1/", "GCP metadata endpoint"),
    ("http://100.100.100.200/latest/meta-data/",         "Alibaba Cloud metadata"),
    # Internal network
    ("http://127.0.0.1/",                                "localhost loopback"),
    ("http://localhost/",                                 "localhost hostname"),
    ("http://0.0.0.0/",                                  "0.0.0.0 loopback"),
    # Bypass techniques
    ("http://127.1/",                                     "shortened localhost"),
    ("http://[::1]/",                                     "IPv6 loopback"),
    ("http://2130706433/",                                "decimal IP (127.0.0.1)"),
]

# Indicators that SSRF succeeded
SSRF_INDICATORS = [
    r"ami-[0-9a-f]{8,}",
    r"instance-id",
    r"local-hostname",
    r"security-credentials",
    r"iam/info",
    r"placement/availability-zone",
    r"computeMetadata",
    r"root:.*?:/bin",       # /etc/passwd content
    r"daemon:.*?:",
    r"\[core\]",            # git config
    r"DB_PASSWORD",
    r"SECRET_KEY",
]


def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    parsed = urlparse(url)
    existing_params = parse_qs(parsed.query, keep_blank_values=True)

    if not existing_params:
        # No parameters — add test params to look for reflection
        test_params = {p: ["https://example.com"] for p in SSRF_PARAMS[:3]}
    else:
        # Use existing parameters
        test_params = existing_params

    ssrf_params = [p for p in test_params if p.lower() in SSRF_PARAMS]
    if not ssrf_params:
        ssrf_params = list(test_params.keys())[:3]

    with get_client(timeout=min(timeout, 6.0)) as client:
        for param in ssrf_params[:3]:  # test max 3 params
            for (probe, probe_desc) in SSRF_PROBES[:6]:
                new_params = dict(test_params)
                new_params[param] = [probe]

                test_query = urlencode({k: v[0] if isinstance(v, list) else v
                                        for k, v in new_params.items()})
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, test_query, ""
                ))

                try:
                    resp = client.get(test_url, follow_redirects=False)
                    body = resp.text

                    # Check for SSRF indicators in response
                    for pattern in SSRF_INDICATORS:
                        if re.search(pattern, body, re.IGNORECASE):
                            findings.append(Finding(
                                title=f"SSRF Vulnerability Detected — Parameter '{param}'",
                                severity=Severity.CRITICAL,
                                description=(
                                    f"The '{param}' parameter is vulnerable to Server-Side "
                                    "Request Forgery. The server made an internal HTTP request "
                                    f"to '{probe_desc}' and the response was returned. "
                                    "Attackers can use this to read cloud credentials, "
                                    "access internal services, and pivot inside your network."
                                ),
                                evidence=(
                                    f"Probe: {probe}\n"
                                    f"Parameter: {param}\n"
                                    f"Response indicator matched: {pattern}\n"
                                    f"Response snippet: {body[:200]}"
                                ),
                                remediation=(
                                    "Validate and whitelist allowed URLs. Never fetch "
                                    "user-supplied URLs without strict validation. "
                                    "Block requests to private IP ranges and cloud metadata endpoints."
                                ),
                                code_fix=(
                                    "import ipaddress\nfrom urllib.parse import urlparse\n\n"
                                    "BLOCKED_RANGES = [\n"
                                    "    ipaddress.ip_network('169.254.0.0/16'),  # Link-local\n"
                                    "    ipaddress.ip_network('10.0.0.0/8'),\n"
                                    "    ipaddress.ip_network('172.16.0.0/12'),\n"
                                    "    ipaddress.ip_network('192.168.0.0/16'),\n"
                                    "    ipaddress.ip_network('127.0.0.0/8'),\n"
                                    "]\n\n"
                                    "def is_safe_url(url):\n"
                                    "    host = urlparse(url).hostname\n"
                                    "    try:\n"
                                    "        ip = ipaddress.ip_address(host)\n"
                                    "        return not any(ip in r for r in BLOCKED_RANGES)\n"
                                    "    except ValueError:\n"
                                    "        return True  # domain — also validate via DNS"
                                ),
                                reference="https://portswigger.net/web-security/ssrf",
                                cvss=9.8,
                            ))
                            return findings  # one SSRF finding is enough

                except Exception:
                    continue

    return findings
