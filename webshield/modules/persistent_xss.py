"""Persistent (Stored) XSS Module (v1.8.0) — ZAP rule 40014"""
from __future__ import annotations
import re
import uuid
from typing import List
from urllib.parse import urlparse
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

FORM_PATTERN  = re.compile(r'<form[^>]*>(.*?)</form>', re.S | re.I)
INPUT_PATTERN = re.compile(r'<input[^>]+name=["\']([^"\']+)["\']', re.I)
TEXTAREA_PAT  = re.compile(r'<textarea[^>]+name=["\']([^"\']+)["\']', re.I)
ACTION_PATTERN= re.compile(r'<form[^>]+action=["\']([^"\']*)["\']', re.I)

XSS_PAYLOADS = [
    '<script>alert("xss-{}")</script>',
    '"><script>alert("xss-{}")</script>',
    '"><img src=x onerror=alert("xss-{}")>',
    "';alert('xss-{}')//",
]

def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    parsed   = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    with get_client(timeout=min(timeout, 8.0), follow_redirects=True) as client:
        try:
            resp = client.get(url)
            if resp.status_code != 200:
                return findings
            body = resp.text

            forms = FORM_PATTERN.findall(body)
            action_urls = ACTION_PATTERN.findall(body)

            for i, form_html in enumerate(forms[:3]):
                inputs    = INPUT_PATTERN.findall(form_html)
                textareas = TEXTAREA_PAT.findall(form_html)
                all_fields = inputs + textareas
                if not all_fields:
                    continue

                action = action_urls[i] if i < len(action_urls) else parsed.path
                if not action.startswith("http"):
                    action = base_url + ("/" if not action.startswith("/") else "") + action.lstrip("/")

                canary = uuid.uuid4().hex[:8]
                for payload_tpl in XSS_PAYLOADS[:2]:
                    payload = payload_tpl.format(canary)
                    post_data = "&".join(f"{f}={payload}" for f in all_fields[:4])

                    try:
                        # Submit the form with XSS payload
                        r_post = client.post(
                            action,
                            content=post_data.encode(),
                            headers={"Content-Type": "application/x-www-form-urlencoded"},
                        )

                        # Retrieve the same page and check if payload persists
                        r_get = client.get(url)
                        if canary in r_get.text:
                            # Check if it's inside a <script> or unencoded
                            ctx = r_get.text[max(0, r_get.text.find(canary)-20):r_get.text.find(canary)+50]
                            if "<script>" in ctx.lower() or "onerror=" in ctx.lower() or "alert" in ctx.lower():
                                findings.append(Finding(
                                    title="Stored (Persistent) XSS Detected",
                                    severity=Severity.HIGH,
                                    description=(
                                        "A Stored XSS vulnerability was confirmed. The injected script "
                                        "was submitted via a form and persisted in the page response. "
                                        "Every user who visits this page will have the script executed "
                                        "in their browser — enabling session theft, defacement, and phishing."
                                    ),
                                    evidence=(
                                        f"Form action: {action}\n"
                                        f"Canary: {canary}\n"
                                        f"Payload persisted in GET {url}\n"
                                        f"Context: ...{ctx}..."
                                    ),
                                    remediation="HTML-encode all user-supplied output. Use a CSP to restrict script execution.",
                                    code_fix=(
                                        "# Python — escape ALL output:\n"
                                        "from markupsafe import escape\n"
                                        "safe = escape(user_input)\n\n"
                                        "# React: JSX auto-escapes; never use dangerouslySetInnerHTML\n"
                                        "# Vue: use {{ }} binding, never v-html with user data"
                                    ),
                                    reference="https://owasp.org/www-community/attacks/xss/#stored-xss-attacks",
                                    module="persistent_xss",
                                    cvss=8.2,
                                ))
                                return findings
                    except Exception:
                        continue
        except Exception:
            pass
    return findings
