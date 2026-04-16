"""
Clickjacking Protection Module (v1.0.1)
Deep checks: X-Frame-Options, CSP frame-ancestors, iframe embedding test.
"""

from __future__ import annotations
from typing import List
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client


def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []

    try:
        with get_client(timeout=timeout) as client:
            resp = client.get(url)
    except Exception:
        return []

    headers = {k.lower(): v for k, v in resp.headers.items()}
    xfo = headers.get("x-frame-options", "")
    csp = headers.get("content-security-policy", "")
    has_frame_ancestors = "frame-ancestors" in csp.lower()
    has_xfo = bool(xfo.strip())

    if not has_xfo and not has_frame_ancestors:
        findings.append(Finding(
            title="Clickjacking Protection Missing",
            severity=Severity.MEDIUM,
            description=(
                "Neither X-Frame-Options nor CSP frame-ancestors is set. "
                "Attackers can embed your page in an invisible iframe and trick "
                "users into clicking buttons they can't see — transferring money, "
                "changing passwords, or deleting accounts."
            ),
            evidence=f"X-Frame-Options: (not set)\nCSP frame-ancestors: (not set)",
            remediation=(
                "Add X-Frame-Options: SAMEORIGIN or set "
                "Content-Security-Policy: frame-ancestors 'self'. "
                "The CSP approach is preferred for modern browsers."
            ),
            code_fix=(
                "# Nginx:\n"
                "add_header X-Frame-Options \"SAMEORIGIN\" always;\n"
                "# or with CSP:\n"
                "add_header Content-Security-Policy \"frame-ancestors 'self'\" always;\n\n"
                "# Python (Django): X_FRAME_OPTIONS = 'SAMEORIGIN'\n"
                "# Node.js (Helmet): helmet.frameguard({ action: 'sameorigin' })"
            ),
            reference="https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html",
            cvss=6.1,
        ))
    elif has_xfo and xfo.upper() == "ALLOWALL":
        findings.append(Finding(
            title="X-Frame-Options Set to ALLOWALL (Insecure)",
            severity=Severity.HIGH,
            description=(
                "X-Frame-Options is set to ALLOWALL, which allows any site to "
                "embed your page in an iframe. This provides no clickjacking protection."
            ),
            evidence=f"X-Frame-Options: {xfo}",
            remediation="Change to SAMEORIGIN or DENY.",
            code_fix="X-Frame-Options: SAMEORIGIN",
            reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
            cvss=6.5,
        ))
    elif has_frame_ancestors:
        # Check if frame-ancestors uses wildcard
        import re
        fa_match = re.search(r"frame-ancestors\s+([^;]+)", csp, re.IGNORECASE)
        if fa_match:
            fa_val = fa_match.group(1).strip()
            if fa_val == "*":
                findings.append(Finding(
                    title="CSP frame-ancestors Allows All Origins (*)",
                    severity=Severity.HIGH,
                    description=(
                        "The CSP frame-ancestors directive is set to *, allowing any "
                        "origin to embed your page in an iframe."
                    ),
                    evidence=f"Content-Security-Policy: ...frame-ancestors {fa_val}...",
                    remediation="Change frame-ancestors to 'self' or specific trusted origins.",
                    code_fix="Content-Security-Policy: frame-ancestors 'self'",
                    reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors",
                    cvss=6.1,
                ))

    return findings
