"""
Cookie Security Module
Checks Secure, HttpOnly, SameSite flags and weak session ID patterns.
Learned from: GSEC (session_management), Wapiti (mod_cookie_flags), yawast-ng
"""

from __future__ import annotations
import re
from typing import List
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client


def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []

    try:
        with get_client(timeout=timeout) as client:
            resp = client.get(url)
    except Exception as e:
        return []

    cookies = resp.cookies
    raw_headers = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []

    # fallback: parse raw Set-Cookie headers
    if not raw_headers:
        raw_headers = [v for k, v in resp.headers.items() if k.lower() == "set-cookie"]

    if not raw_headers:
        return []

    for raw in raw_headers:
        raw_lower = raw.lower()
        # Extract cookie name for context
        cookie_name = raw.split("=")[0].strip() if "=" in raw else "unknown"

        # 1. Missing Secure flag
        if "secure" not in raw_lower:
            findings.append(Finding(
                title=f"Cookie Missing Secure Flag: {cookie_name}",
                severity=Severity.MEDIUM,
                description=(
                    f"The cookie '{cookie_name}' does not have the Secure flag set. "
                    "It can be transmitted over unencrypted HTTP connections, "
                    "exposing it to network sniffing attacks."
                ),
                evidence=f"Set-Cookie: {raw[:120]}",
                remediation="Add the Secure flag to all cookies, especially session cookies.",
                code_fix=(
                    "# Python (Flask):\n"
                    "response.set_cookie('session', value, secure=True)\n\n"
                    "# Python (Django):\n"
                    "SESSION_COOKIE_SECURE = True  # in settings.py\n\n"
                    "# Node.js (Express):\n"
                    "res.cookie('session', value, { secure: true })"
                ),
                reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#secure",
            ))

        # 2. Missing HttpOnly flag
        if "httponly" not in raw_lower:
            findings.append(Finding(
                title=f"Cookie Missing HttpOnly Flag: {cookie_name}",
                severity=Severity.MEDIUM,
                description=(
                    f"The cookie '{cookie_name}' does not have the HttpOnly flag set. "
                    "JavaScript can read this cookie, making it vulnerable to XSS-based "
                    "session theft via document.cookie."
                ),
                evidence=f"Set-Cookie: {raw[:120]}",
                remediation="Add HttpOnly flag to all sensitive cookies to prevent JS access.",
                code_fix=(
                    "# Python (Flask):\n"
                    "response.set_cookie('session', value, httponly=True)\n\n"
                    "# Python (Django):\n"
                    "SESSION_COOKIE_HTTPONLY = True  # in settings.py\n\n"
                    "# Node.js (Express):\n"
                    "res.cookie('session', value, { httpOnly: true })"
                ),
                reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#httponly",
                cvss=6.1,
            ))

        # 3. Missing SameSite attribute
        if "samesite" not in raw_lower:
            findings.append(Finding(
                title=f"Cookie Missing SameSite Attribute: {cookie_name}",
                severity=Severity.LOW,
                description=(
                    f"The cookie '{cookie_name}' has no SameSite attribute. "
                    "This makes it vulnerable to Cross-Site Request Forgery (CSRF) attacks "
                    "where malicious sites can make requests using this cookie."
                ),
                evidence=f"Set-Cookie: {raw[:120]}",
                remediation="Set SameSite=Lax (recommended default) or SameSite=Strict.",
                code_fix=(
                    "# Python (Flask):\n"
                    "response.set_cookie('session', value, samesite='Lax')\n\n"
                    "# Python (Django):\n"
                    "SESSION_COOKIE_SAMESITE = 'Lax'  # in settings.py\n\n"
                    "# Node.js (Express):\n"
                    "res.cookie('session', value, { sameSite: 'lax' })"
                ),
                reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#samesitesamesite-value",
            ))

        # 4. SameSite=None without Secure
        if "samesite=none" in raw_lower and "secure" not in raw_lower:
            findings.append(Finding(
                title=f"Cookie SameSite=None Without Secure: {cookie_name}",
                severity=Severity.MEDIUM,
                description=(
                    "SameSite=None requires the Secure flag. Without it, "
                    "the cookie will be rejected by modern browsers."
                ),
                evidence=f"Set-Cookie: {raw[:120]}",
                remediation="Add Secure flag when using SameSite=None.",
                code_fix="Set-Cookie: session=value; SameSite=None; Secure",
                reference="https://web.dev/samesite-cookies-explained/",
            ))

        # 5. Weak session ID (too short or sequential)
        cookie_value = raw.split("=", 1)[1].split(";")[0].strip() if "=" in raw else ""
        is_session_cookie = any(x in cookie_name.lower() for x in
                                ["session", "sessid", "sid", "phpsessid", "jsessionid", "auth", "token"])
        if is_session_cookie and cookie_value:
            if len(cookie_value) < 16:
                findings.append(Finding(
                    title=f"Potentially Weak Session ID: {cookie_name}",
                    severity=Severity.MEDIUM,
                    description=(
                        f"The session cookie '{cookie_name}' has a value of only "
                        f"{len(cookie_value)} characters, which may be too short for "
                        "sufficient entropy and could be brute-forced."
                    ),
                    evidence=f"Cookie value length: {len(cookie_value)}",
                    remediation="Generate session IDs with at least 128 bits of entropy (32+ hex chars).",
                    code_fix=(
                        "import secrets\n"
                        "session_id = secrets.token_hex(32)  # 64 char hex = 256 bits"
                    ),
                    reference="https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
                    cvss=5.9,
                ))

    return findings
