"""
CSRF (Cross-Site Request Forgery) Protection Check (v1.2.0)
Analyzes forms for missing CSRF tokens. State-changing endpoints check.
Learned from: Wapiti (mod_csrf.py — Shannon entropy + token detection)
"""
from __future__ import annotations
import re
import math
from collections import Counter
from typing import List, Optional
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

# Known CSRF token field names (from Wapiti's production list)
CSRF_TOKEN_FIELDS = {
    "authenticity_token", "_token", "csrf_token", "csrfname", "csrftoken",
    "anticsrf", "__requestverificationtoken", "token", "csrf", "_csrf_token",
    "xsrf_token", "_csrf", "csrf-token", "xsrf-token", "_wpnonce",
    "csrfmiddlewaretoken", "__csrf_token__", "csrfkey", "_xsrf",
}

CSRF_TOKEN_HEADERS = {
    "csrf-token", "x-csrf-token", "xsrf-token", "x-xsrf-token",
    "csrfp-token", "x-csrf-header", "x-csrf-protection",
}

# Form action patterns that indicate state-changing operations
STATE_CHANGE_PATTERNS = re.compile(
    r"(?:login|logout|delete|update|edit|create|submit|transfer|"
    r"purchase|buy|send|post|upload|change|reset|register|pay|order)",
    re.I
)

# HTML form parser
FORM_PATTERN = re.compile(r"<form[^>]*>(.*?)</form>", re.I | re.DOTALL)
INPUT_PATTERN = re.compile(r"<input([^>]*)>", re.I)
NAME_ATTR = re.compile(r'name\s*=\s*["\']([^"\']+)["\']', re.I)
TYPE_ATTR = re.compile(r'type\s*=\s*["\']([^"\']+)["\']', re.I)
VALUE_ATTR = re.compile(r'value\s*=\s*["\']([^"\']+)["\']', re.I)
ACTION_ATTR = re.compile(r'action\s*=\s*["\']([^"\']*)["\']', re.I)
METHOD_ATTR = re.compile(r'method\s*=\s*["\']([^"\']*)["\']', re.I)


def _entropy(s: str) -> float:
    """Shannon entropy — high entropy = likely a CSRF token."""
    if not s or len(s) < 8:
        return 0.0
    probs = [n / len(s) for n in Counter(s).values()]
    return -sum(p * math.log2(p) for p in probs)


def _has_csrf_token(form_html: str) -> Optional[str]:
    """Check if form contains a CSRF token. Returns token name or None."""
    for input_match in INPUT_PATTERN.finditer(form_html):
        attrs = input_match.group(1)
        name_m = NAME_ATTR.search(attrs)
        type_m = TYPE_ATTR.search(attrs)
        value_m = VALUE_ATTR.search(attrs)

        if not name_m:
            continue

        name = name_m.group(1).lower()
        input_type = type_m.group(1).lower() if type_m else "text"
        value = value_m.group(1) if value_m else ""

        # Check known CSRF field names
        if name in CSRF_TOKEN_FIELDS:
            return name

        # Check hidden field with high-entropy value (likely a token)
        if input_type == "hidden" and _entropy(value) > 3.0 and len(value) >= 8:
            return name

    return None


def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []

    try:
        with get_client(timeout=timeout) as client:
            resp = client.get(url)
    except Exception:
        return []

    if "text/html" not in resp.headers.get("content-type", ""):
        return []

    body = resp.text
    resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}

    # Check response headers for CSRF token (SPA pattern)
    header_has_csrf = any(h in resp_headers_lower for h in CSRF_TOKEN_HEADERS)

    # Parse all forms
    forms_analyzed = 0
    forms_missing_csrf = []

    for form_match in FORM_PATTERN.finditer(body):
        form_html = form_match.group(0)
        forms_analyzed += 1

        # Only check POST forms or state-changing forms
        method_m = METHOD_ATTR.search(form_html)
        action_m = ACTION_ATTR.search(form_html)
        method = method_m.group(1).upper() if method_m else "GET"
        action = action_m.group(1) if action_m else ""

        # Skip pure GET forms (safe by HTTP spec)
        if method == "GET" and not STATE_CHANGE_PATTERNS.search(action):
            continue

        # Check for CSRF token
        token_name = _has_csrf_token(form_html)
        if not token_name and not header_has_csrf:
            forms_missing_csrf.append(action or url)

    if forms_missing_csrf:
        findings.append(Finding(
            title=f"CSRF Protection Missing on {len(forms_missing_csrf)} Form(s)",
            severity=Severity.MEDIUM,
            description=(
                f"Found {len(forms_missing_csrf)} POST form(s) without CSRF protection. "
                "Attackers can create malicious websites that trick authenticated users "
                "into submitting forms — changing passwords, transferring money, deleting "
                "accounts — without the user's knowledge or consent."
            ),
            evidence=(
                f"Forms without CSRF tokens:\n" +
                "\n".join(f"  - {a}" for a in forms_missing_csrf[:5])
            ),
            remediation=(
                "Add a CSRF token to every state-changing form. "
                "Verify the token server-side on every POST/PUT/DELETE request."
            ),
            code_fix=(
                "# Python (Django — built-in):\n"
                "# 1. Add {% csrf_token %} inside every <form>\n"
                "# 2. Use @csrf_protect decorator or middleware (default)\n\n"
                "# Python (Flask — flask-wtf):\n"
                "from flask_wtf import CSRFProtect\n"
                "csrf = CSRFProtect(app)\n"
                "# In template: {{ form.hidden_tag() }}\n\n"
                "# Node.js (csurf):\n"
                "const csrf = require('csurf');\n"
                "app.use(csrf({ cookie: true }));\n"
                "// In template: <input name='_csrf' value='<%= csrfToken() %>'>"
            ),
            reference="https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
            cvss=6.5,
        ))

    # SameSite cookie as CSRF mitigation check
    set_cookie = resp.headers.get("set-cookie", "")
    if forms_analyzed > 0 and "samesite" not in set_cookie.lower() and not header_has_csrf:
        findings.append(Finding(
            title="SameSite Cookie Attribute Missing (CSRF Mitigation)",
            severity=Severity.LOW,
            description=(
                "No SameSite cookie attribute found. SameSite=Lax/Strict provides "
                "defense-in-depth against CSRF attacks in modern browsers."
            ),
            evidence="set-cookie header missing SameSite attribute",
            remediation="Set SameSite=Lax on session cookies.",
            code_fix="Set-Cookie: session=value; SameSite=Lax; Secure; HttpOnly",
            reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite",
        ))

    return findings
