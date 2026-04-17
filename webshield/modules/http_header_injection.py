"""
HTTP Header Injection / Host Header Attack Module (v1.4.0)

Covers:
  - Host header injection (password reset poisoning)
  - X-Forwarded-Host / X-Forwarded-For abuse
  - Cache poisoning via header injection
  - Routing bypass via internal host headers

How attackers use this:
  1. Password Reset Poisoning: Attacker intercepts a password reset request,
     changes the Host header to attacker.com. If the app uses the Host header
     to build reset links, the reset email will contain attacker.com/reset?token=XXX.
     When the victim clicks it, the attacker captures the token.

  2. Cache Poisoning: Some CDNs cache responses based on URL but include
     injected headers (X-Forwarded-Host) in the response. Attackers can
     poison the cache for all users.

  3. SSRF via Host: Internal routing systems may trust X-Forwarded-Host
     to forward requests to internal services.

References:
  - PortSwigger: https://portswigger.net/web-security/host-header
  - James Kettle research on cache poisoning
  - HackerOne bug bounty reports: host header injection
"""

from __future__ import annotations
import re
from typing import List
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

EVIL_HOST = "evil-webshield-test.example.com"
EVIL_HOST_FULL = f"https://{EVIL_HOST}"

# If any of these appear in the response body when we inject EVIL_HOST,
# the app is reflecting our injected host value — vulnerable!
def _host_reflected(body: str, target_host: str) -> bool:
    return EVIL_HOST in body or target_host in body


def _check_host_header_reflection(client, url: str, findings: List[Finding]) -> None:
    """
    Test if the Host header value is reflected in the response body.
    Uses a baseline request first to avoid false-positives where the
    domain name naturally appears in the page.
    """
    try:
        # Baseline — normal request
        baseline = client.get(url).text
        if EVIL_HOST in baseline:
            return  # site already contains this string — skip

        # Inject evil host via X-Forwarded-Host (more reliable across proxies)
        resp = client.get(
            url,
            headers={
                "X-Forwarded-Host": EVIL_HOST,
                "X-Original-Host": EVIL_HOST,
            }
        )
        body = resp.text

        if EVIL_HOST in body:
            # Determine context — is it in a link, a form action, or just text?
            in_link = bool(re.search(
                r'(?:href|src|action|location)["\s]*[=:]["\s]*[^"\']*' + re.escape(EVIL_HOST),
                body, re.I
            ))
            in_meta = bool(re.search(
                r'<meta[^>]+content=["\'][^"\']*' + re.escape(EVIL_HOST),
                body, re.I
            ))

            context = "URL/link context" if in_link else "meta tag" if in_meta else "response body"
            severity = Severity.HIGH if (in_link or in_meta) else Severity.MEDIUM

            findings.append(Finding(
                title="Host Header Injection — Injected Host Reflected in Response",
                severity=severity,
                description=(
                    f"The application reflects the HTTP Host header value ({EVIL_HOST}) "
                    f"in the response ({context}). This enables:\n"
                    "• Password reset poisoning — reset emails contain attacker-controlled links\n"
                    "• Web cache poisoning — cached responses contain malicious content\n"
                    "• Open redirect — users redirected to attacker's domain\n"
                    "Real attack: Change Host header in a password reset request to attacker.com, "
                    "victim receives an email with a reset link pointing to attacker.com and their token."
                ),
                evidence=(
                    f"Injected Host: {EVIL_HOST}\n"
                    f"Injection context: {context}\n"
                    f"Response snippet: {body[:400]}"
                ),
                remediation=(
                    "Never use the HTTP Host header to build URLs in server-side code. "
                    "Use a hardcoded site URL from config instead. "
                    "Validate the Host header against an allowlist of known domains."
                ),
                code_fix=(
                    "# ❌ VULNERABLE — using request host to build reset link:\n"
                    "reset_url = f'https://{request.host}/reset?token={token}'\n\n"
                    "# ✅ SAFE — use config:\n"
                    "from django.conf import settings\n"
                    "reset_url = f'{settings.SITE_URL}/reset?token={token}'\n\n"
                    "# Django — allowlist valid hosts:\n"
                    "ALLOWED_HOSTS = ['example.com', 'www.example.com']\n\n"
                    "# Express — validate host:\n"
                    "const ALLOWED_HOSTS = ['example.com'];\n"
                    "if (!ALLOWED_HOSTS.includes(req.hostname)) {\n"
                    "  return res.status(400).send('Invalid host');\n"
                    "}"
                ),
                reference="https://portswigger.net/web-security/host-header",
                cvss=7.2 if severity == Severity.HIGH else 5.4,
            ))
    except Exception:
        pass


def _check_x_forwarded_host(client, url: str, findings: List[Finding]) -> None:
    """
    Test X-Forwarded-Host header — separate from the combined test above.
    Only reached if the combined test didn't already report a finding.
    """
    try:
        # Need baseline for comparison here too
        baseline = client.get(url).text
        resp = client.get(
            url,
            headers={"X-Forwarded-Host": EVIL_HOST}
        )
        if EVIL_HOST in resp.text and EVIL_HOST not in baseline:
            findings.append(Finding(
                title="X-Forwarded-Host Header Reflected in Response",
                severity=Severity.MEDIUM,
                description=(
                    "The X-Forwarded-Host header value is reflected in the response. "
                    "Even if the Host header is validated, X-Forwarded-Host can be used "
                    "for the same attacks — cache poisoning, password reset poisoning, "
                    "and open redirects."
                ),
                evidence=(
                    f"Injected X-Forwarded-Host: {EVIL_HOST}\n"
                    f"Found in response body"
                ),
                remediation=(
                    "Ignore X-Forwarded-Host in application URL generation unless "
                    "you specifically trust your load balancer. "
                    "Use a configured SITE_URL constant instead."
                ),
                code_fix=(
                    "# Django — explicitly disable X-Forwarded-Host:\n"
                    "USE_X_FORWARDED_HOST = False  # default\n"
                    "SITE_URL = 'https://example.com'  # use this for URL generation\n\n"
                    "# Flask — don't trust proxy headers by default:\n"
                    "# Only set ProxyFix if you're behind a trusted proxy\n"
                    "# from werkzeug.middleware.proxy_fix import ProxyFix"
                ),
                reference="https://portswigger.net/research/practical-web-cache-poisoning",
                cvss=5.4,
            ))
    except Exception:
        pass


def _check_routing_bypass(client, url: str, findings: List[Finding]) -> None:
    """
    Test if X-Original-URL or X-Rewrite-URL can bypass access controls.
    Some load balancers/proxies honor these headers for routing.
    """
    bypass_headers = [
        {"X-Original-URL": "/admin"},
        {"X-Rewrite-URL": "/admin"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Real-IP": "127.0.0.1"},
        {"X-Remote-IP": "127.0.0.1"},
        {"X-Client-IP": "127.0.0.1"},
    ]

    try:
        # Get baseline for /admin
        from urllib.parse import urlparse
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        admin_resp = client.get(base + "/admin")
        normal_status = admin_resp.status_code

        if normal_status not in (401, 403, 404):
            return  # admin is either accessible or doesn't exist — skip

        for headers in bypass_headers:
            try:
                resp = client.get(url, headers=headers)
                if resp.status_code == 200 and normal_status in (401, 403):
                    header_name = list(headers.keys())[0]
                    findings.append(Finding(
                        title=f"Access Control Bypass via '{header_name}' Header",
                        severity=Severity.HIGH,
                        description=(
                            f"The header '{header_name}' bypasses access controls. "
                            f"A request to /admin normally returns HTTP {normal_status}, "
                            "but adding this header returned HTTP 200. "
                            "Attackers can access restricted admin panels and internal endpoints."
                        ),
                        evidence=(
                            f"Normal /admin → HTTP {normal_status}\n"
                            f"With {header_name} header → HTTP 200\n"
                            f"Header value: {headers[header_name]}"
                        ),
                        remediation=(
                            "Do not rely on HTTP headers for access control decisions. "
                            "Implement proper server-side authorization checks. "
                            "Validate origin/IP at the application layer, not via headers."
                        ),
                        code_fix=(
                            "# Never trust client-supplied IP headers for access control:\n"
                            "# ❌ WRONG:\n"
                            "if request.headers.get('X-Forwarded-For') == '127.0.0.1':\n"
                            "    allow_admin_access()\n\n"
                            "# ✅ CORRECT — check authenticated user role:\n"
                            "@login_required\n"
                            "@permission_required('is_admin')\n"
                            "def admin_view(request): ..."
                        ),
                        reference="https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/403-and-401-bypasses",
                        cvss=8.1,
                    ))
                    return
            except Exception:
                continue
    except Exception:
        pass


def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []

    with get_client(timeout=min(timeout, 8.0)) as client:
        _check_host_header_reflection(client, url, findings)
        if not findings:
            _check_x_forwarded_host(client, url, findings)
        _check_routing_bypass(client, url, findings)

    return findings
