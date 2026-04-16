"""
XSS (Cross-Site Scripting) Detection Module (v1.2.0)
Reflected XSS detection via parameter injection and reflection checking.
Learned from: XSStrike (context-aware, best XSS tool), Wapiti (mod_xss),
              GSEC (xss.py), Greaper (xss.py)
"""

from __future__ import annotations
import re
from typing import List
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

# Unique canary to detect reflection
XSS_CANARY = "wshld9x7z"

# Payloads — ordered by WAF bypass effectiveness
XSS_PAYLOADS = [
    # Basic reflection check (canary only)
    XSS_CANARY,
    # HTML context breakouts
    f"<{XSS_CANARY}>",
    f"\"><{XSS_CANARY}>",
    f"'><{XSS_CANARY}>",
    # Script injection
    f"<script>{XSS_CANARY}</script>",
    f"\"><script>{XSS_CANARY}</script>",
    # Event handler injection
    f"\" onmouseover=\"{XSS_CANARY}",
    f"' onmouseover='{XSS_CANARY}",
    # SVG/img injection
    f"<svg onload={XSS_CANARY}>",
    f"<img src=x onerror={XSS_CANARY}>",
    # Template literals
    f"${{'{XSS_CANARY}'}}",
    # JS context breakout
    f"';{XSS_CANARY}//",
    # No-script bypasses
    f"<details open ontoggle={XSS_CANARY}>",
]

# Response patterns indicating XSS is reflected unescaped
REFLECTION_PATTERNS = [
    # Script tag reflected
    re.compile(r"<script[^>]*>" + XSS_CANARY, re.I),
    # Event handler reflected
    re.compile(r'on\w+\s*=\s*["\']?' + XSS_CANARY, re.I),
    # Raw HTML tag with canary
    re.compile(r"<" + XSS_CANARY + r"\s*>", re.I),
    # SVG/img reflected
    re.compile(r"<(?:svg|img)[^>]+(?:onload|onerror)\s*=\s*" + XSS_CANARY, re.I),
    # Breakout from attribute
    re.compile(r'"><' + XSS_CANARY, re.I),
    re.compile(r"'><" + XSS_CANARY, re.I),
]

# Encoding-escaped patterns (encoded output = filtered = lower risk)
ESCAPED_PATTERNS = [
    re.compile(r"&lt;" + XSS_CANARY, re.I),
    re.compile(r"&gt;" + XSS_CANARY, re.I),
    re.compile(r"&quot;" + XSS_CANARY, re.I),
    re.compile(r"&#x3[Cc];" + XSS_CANARY, re.I),
]


def _is_escaped(body: str) -> bool:
    return any(p.search(body) for p in ESCAPED_PATTERNS)


def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    parsed = urlparse(url)
    params = list(parse_qs(parsed.query, keep_blank_values=True).keys())

    if not params:
        return []

    # Check Content-Type — only test HTML responses
    with get_client(timeout=min(timeout, 8.0)) as client:
        try:
            baseline_resp = client.get(url)
            content_type = baseline_resp.headers.get("content-type", "")
            if "text/html" not in content_type and "application/xhtml" not in content_type:
                return []
            baseline = baseline_resp.text
        except Exception:
            return []

        for param in params[:4]:
            for payload in XSS_PAYLOADS:
                all_params = parse_qs(parsed.query, keep_blank_values=True)
                new_params = {k: v[0] if isinstance(v, list) else v for k, v in all_params.items()}
                new_params[param] = payload
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, urlencode(new_params), ""
                ))
                try:
                    resp = client.get(test_url)
                    body = resp.text
                except Exception:
                    continue

                if XSS_CANARY not in body:
                    continue  # Not reflected at all

                if _is_escaped(body):
                    # Reflected but HTML-escaped — output encoding working
                    findings.append(Finding(
                        title=f"XSS Input Reflected (HTML-Encoded) — param: {param}",
                        severity=Severity.LOW,
                        description=(
                            f"User input in '{param}' is reflected in the HTML response "
                            "but appears to be HTML-encoded. This suggests output encoding "
                            "is in place, but ensure encoding is applied in all contexts "
                            "(HTML, JS, CSS, URL)."
                        ),
                        evidence=f"Payload reflected (encoded): {payload[:60]}",
                        remediation="Verify encoding is context-appropriate everywhere.",
                        reference="https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                    ))
                    break

                # Check for unescaped XSS injection
                for pattern in REFLECTION_PATTERNS:
                    if pattern.search(body):
                        findings.append(Finding(
                            title=f"Reflected XSS Vulnerability — param: {param}",
                            severity=Severity.HIGH,
                            description=(
                                f"The '{param}' parameter is vulnerable to Reflected XSS. "
                                f"The payload '{payload[:60]}' was reflected unescaped in "
                                "the HTML response. Attackers can craft malicious URLs that "
                                "steal session cookies, redirect users, log keystrokes, or "
                                "deface the page when a victim clicks the link."
                            ),
                            evidence=(
                                f"Parameter: {param}\n"
                                f"Payload: {payload}\n"
                                f"Pattern matched: {pattern.pattern}\n"
                                f"Reflected snippet: {_find_context(body, XSS_CANARY)}"
                            ),
                            remediation=(
                                "HTML-encode all user input before inserting into HTML. "
                                "Use a template engine that auto-escapes output. "
                                "Implement a strong Content-Security-Policy."
                            ),
                            code_fix=(
                                "# Python (Jinja2 auto-escapes by default):\n"
                                "# Enable: Environment(autoescape=True)\n\n"
                                "# Manual HTML encoding:\n"
                                "from html import escape\n"
                                "safe_output = escape(user_input)\n\n"
                                "# Django: {{ value }} is auto-escaped\n"
                                "# Use {% autoescape on %} block\n\n"
                                "# React: {variable} is auto-escaped\n"
                                "# NEVER use dangerouslySetInnerHTML with user input"
                            ),
                            reference="https://owasp.org/www-community/attacks/xss/",
                            cvss=6.1,
                        ))
                        return findings

    return findings


def _find_context(body: str, canary: str) -> str:
    idx = body.lower().find(canary.lower())
    if idx == -1:
        return ""
    start = max(0, idx - 40)
    end = min(len(body), idx + 80)
    return body[start:end].replace("\n", " ").strip()
