"""Permissions-Policy, Referrer-Policy & Cross-Origin Isolation Headers (v1.8.0)"""
from __future__ import annotations
import re
from typing import List
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

DANGEROUS_PP = re.compile(r"camera=\*|microphone=\*|geolocation=\*|payment=\*|usb=\*", re.I)
WEAK_RP = {"unsafe-url", "no-referrer-when-downgrade", ""}

def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    with get_client(timeout=min(timeout, 8.0)) as client:
        try:
            resp = client.get(url)
            headers = {k.lower(): v for k, v in resp.headers.items()}

            # 1. Permissions-Policy
            pp = headers.get("permissions-policy", headers.get("feature-policy", ""))
            if not pp:
                findings.append(Finding(
                    title="Missing Permissions-Policy Header",
                    severity=Severity.LOW,
                    description=(
                        "The Permissions-Policy header is not set. Without it, embedded iframes "
                        "and third-party scripts can access camera, microphone, geolocation, and payment APIs."
                    ),
                    evidence=f"URL: {url}\nPermissions-Policy header: not present",
                    remediation="Set a restrictive Permissions-Policy header.",
                    code_fix=(
                        "# Nginx:\nadd_header Permissions-Policy \"camera=(), microphone=(), geolocation=(), payment=(), usb=()\";\n\n"
                        "# Express:\nres.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');"
                    ),
                    reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
                    module="permissions_policy",
                    cvss=3.1,
                ))
            elif DANGEROUS_PP.search(pp):
                findings.append(Finding(
                    title="Overly Permissive Permissions-Policy (Wildcard Allowed)",
                    severity=Severity.MEDIUM,
                    description=f"Permissions-Policy grants wildcard (*) access to sensitive APIs: {pp[:100]}",
                    evidence=f"Permissions-Policy: {pp}",
                    remediation="Restrict each feature to specific origins or self only.",
                    code_fix="Permissions-Policy: camera=(self), microphone=(), geolocation=(self)",
                    reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
                    module="permissions_policy",
                    cvss=5.3,
                ))

            # 2. Referrer-Policy
            rp = headers.get("referrer-policy", "").lower().strip()
            if not rp or rp in WEAK_RP:
                findings.append(Finding(
                    title="Missing or Weak Referrer-Policy Header",
                    severity=Severity.LOW,
                    description=(
                        f"Referrer-Policy is {'not set' if not rp else repr(rp)}. "
                        "Without a strict policy, sensitive URL parameters (tokens, IDs) "
                        "are leaked in the Referer header to third-party sites."
                    ),
                    evidence=f"Referrer-Policy: {rp or '(not set)'}",
                    remediation="Set Referrer-Policy: strict-origin-when-cross-origin or no-referrer.",
                    code_fix=(
                        "# Nginx:\nadd_header Referrer-Policy \"strict-origin-when-cross-origin\";\n\n"
                        "# Meta tag:\n<meta name=\"referrer\" content=\"strict-origin-when-cross-origin\">"
                    ),
                    reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
                    module="permissions_policy",
                    cvss=3.1,
                ))

            # 3. Cross-Origin Isolation (COOP + COEP for Spectre protection)
            coop = headers.get("cross-origin-opener-policy", "")
            coep = headers.get("cross-origin-embedder-policy", "")
            corp = headers.get("cross-origin-resource-policy", "")
            if not coop and not coep:
                findings.append(Finding(
                    title="Missing Cross-Origin Isolation Headers (COOP/COEP)",
                    severity=Severity.LOW,
                    description=(
                        "Cross-Origin-Opener-Policy and Cross-Origin-Embedder-Policy are not set. "
                        "Without these, the site is vulnerable to Spectre-class side-channel attacks "
                        "from other origins sharing the same process."
                    ),
                    evidence="Cross-Origin-Opener-Policy: not set\nCross-Origin-Embedder-Policy: not set",
                    remediation="Set COOP and COEP headers to enable cross-origin isolation.",
                    code_fix=(
                        "# Nginx:\n"
                        "add_header Cross-Origin-Opener-Policy \"same-origin\";\n"
                        "add_header Cross-Origin-Embedder-Policy \"require-corp\";\n"
                        "add_header Cross-Origin-Resource-Policy \"same-origin\";"
                    ),
                    reference="https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts",
                    module="permissions_policy",
                    cvss=3.1,
                ))
        except Exception:
            pass
    return findings
