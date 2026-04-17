"""Form Security Module (v1.8.0) — HTTP/HTTPS transitions, autocomplete, GET-for-POST"""
from __future__ import annotations
import re
from typing import List
from urllib.parse import urlparse
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

FORM_PATTERN   = re.compile(r'<form([^>]*)>(.*?)</form>', re.S | re.I)
ACTION_PATTERN = re.compile(r'action\s*=\s*["\']([^"\']+)["\']', re.I)
METHOD_PATTERN = re.compile(r'method\s*=\s*["\']([^"\']+)["\']', re.I)
PASSWORD_INPUT = re.compile(r'<input[^>]+type\s*=\s*["\']password["\']', re.I)
AUTOCOMPLETE   = re.compile(r'autocomplete\s*=\s*["\']off["\']', re.I)

def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    parsed = urlparse(url)
    is_https = parsed.scheme == "https"

    with get_client(timeout=min(timeout, 8.0)) as client:
        try:
            resp = client.get(url)
            if resp.status_code != 200:
                return findings
            body = resp.text

            for m in FORM_PATTERN.finditer(body):
                attrs, content = m.group(1), m.group(2)
                action  = (ACTION_PATTERN.search(attrs) or ACTION_PATTERN.search(m.group(0)))
                method  = (METHOD_PATTERN.search(attrs) or METHOD_PATTERN.search(m.group(0)))
                has_pwd = PASSWORD_INPUT.search(content)
                form_action = action.group(1) if action else parsed.path
                form_method = (method.group(1) if method else "get").lower()

                # 1. HTTPS form posting to HTTP
                if is_https and form_action.startswith("http://"):
                    findings.append(Finding(
                        title="Form on HTTPS Page Posts to HTTP (Insecure Transition)",
                        severity=Severity.HIGH,
                        description=(
                            "A form on this HTTPS page submits data to an HTTP URL. "
                            "Form data including passwords will be sent in plaintext."
                        ),
                        evidence=f"Form action: {form_action}",
                        remediation="Change form action to use HTTPS.",
                        code_fix=f'<form action="{form_action.replace("http://","https://")}" method="post">',
                        reference="https://owasp.org/www-project-web-security-testing-guide/",
                        module="form_security",
                        cvss=7.4,
                    ))

                # 2. HTTP form posting to HTTPS (leaks referrer, still insecure)
                if not is_https and form_action.startswith("https://"):
                    findings.append(Finding(
                        title="Form on HTTP Page Posts to HTTPS (Mixed Transition)",
                        severity=Severity.MEDIUM,
                        description="Form on HTTP page posts to HTTPS. The page itself is insecure and can be MitM'd before form submission.",
                        evidence=f"Page: {url} (HTTP)\nForm action: {form_action} (HTTPS)",
                        remediation="Serve the entire page over HTTPS, not just the form target.",
                        code_fix="Redirect all HTTP to HTTPS at the web server level.",
                        reference="https://owasp.org/www-project-web-security-testing-guide/",
                        module="form_security",
                        cvss=5.3,
                    ))

                # 3. Password field without autocomplete=off
                if has_pwd and not AUTOCOMPLETE.search(m.group(0)):
                    findings.append(Finding(
                        title="Password Field Without autocomplete='off'",
                        severity=Severity.LOW,
                        description="A password input field does not have autocomplete='off'. The browser may cache the password in form history.",
                        evidence=f"Form at: {form_action}",
                        remediation="Add autocomplete='off' to password fields (and autocomplete='new-password' for registration).",
                        code_fix='<input type="password" name="password" autocomplete="current-password">',
                        reference="https://owasp.org/www-project-web-security-testing-guide/",
                        module="form_security",
                        cvss=2.0,
                    ))

                # 4. State-changing form using GET
                if form_method == "get" and has_pwd:
                    findings.append(Finding(
                        title="Password Submitted via GET Method (Exposed in URL/Logs)",
                        severity=Severity.HIGH,
                        description="A form with a password field uses GET method. Passwords will appear in the URL, browser history, and server logs.",
                        evidence=f"Form method=GET with password input, action={form_action}",
                        remediation="Use POST for all forms that contain sensitive data.",
                        code_fix='<form method="post" action="/login">',
                        reference="https://owasp.org/www-project-web-security-testing-guide/",
                        module="form_security",
                        cvss=7.5,
                    ))
        except Exception:
            pass
    return findings
