"""
CORS Misconfiguration Module
Tests for overly permissive or dangerous CORS policies.
Learned from: GSEC (fixed their buggy implementation), w4af cors_origin, wshawk cors_tester
"""

from __future__ import annotations
from typing import List
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

TEST_ORIGINS = [
    "https://evil.com",
    "https://attacker.com",
    "null",
]


def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []

    with get_client(timeout=timeout) as client:
        for origin in TEST_ORIGINS:
            try:
                resp = client.get(url, headers={"Origin": origin})
                acao = resp.headers.get("access-control-allow-origin", "")
                acac = resp.headers.get("access-control-allow-credentials", "")

                # 1. Wildcard CORS — always dangerous with credentials
                if acao == "*":
                    findings.append(Finding(
                        title="CORS Wildcard (*) Origin Allowed",
                        severity=Severity.MEDIUM,
                        description=(
                            "The server responds with 'Access-Control-Allow-Origin: *', "
                            "which allows any website to make cross-origin requests. "
                            "While credentials cannot be sent with wildcards, "
                            "this still exposes public API responses to any origin."
                        ),
                        evidence=f"Origin: {origin}\nAccess-Control-Allow-Origin: {acao}",
                        remediation=(
                            "Restrict CORS to specific trusted origins instead of using *. "
                            "If * is needed for a public API, ensure no sensitive data is returned."
                        ),
                        code_fix=(
                            "# Python (Flask):\n"
                            "from flask_cors import CORS\n"
                            "CORS(app, origins=['https://yourdomain.com'])\n\n"
                            "# Node.js (Express):\n"
                            "app.use(cors({ origin: 'https://yourdomain.com' }))"
                        ),
                        reference="https://portswigger.net/web-security/cors",
                    ))
                    break

                # 2. Attacker origin reflected back — CRITICAL with credentials
                if acao == origin and origin != "null":
                    if acac.lower() == "true":
                        findings.append(Finding(
                            title="CORS Misconfiguration — Arbitrary Origin Reflected with Credentials",
                            severity=Severity.CRITICAL,
                            description=(
                                "The server reflects any arbitrary Origin back in "
                                "Access-Control-Allow-Origin AND allows credentials. "
                                "This allows any malicious website to make authenticated "
                                "cross-origin requests to your API and steal user data."
                            ),
                            evidence=(
                                f"Sent Origin: {origin}\n"
                                f"Access-Control-Allow-Origin: {acao}\n"
                                f"Access-Control-Allow-Credentials: {acac}"
                            ),
                            remediation=(
                                "NEVER reflect arbitrary origins. Maintain a whitelist of "
                                "trusted origins and only allow those. Never combine "
                                "Access-Control-Allow-Credentials: true with a dynamic origin."
                            ),
                            code_fix=(
                                "# Python:\n"
                                "ALLOWED_ORIGINS = ['https://app.yourdomain.com']\n\n"
                                "def cors_check(origin):\n"
                                "    if origin in ALLOWED_ORIGINS:\n"
                                "        return origin\n"
                                "    return 'https://app.yourdomain.com'  # safe default"
                            ),
                            reference="https://portswigger.net/web-security/cors/lab-reflect-arbitrary-origins",
                            cvss=9.0,
                        ))
                    else:
                        findings.append(Finding(
                            title="CORS Misconfiguration — Arbitrary Origin Reflected",
                            severity=Severity.HIGH,
                            description=(
                                "The server reflects any arbitrary Origin in "
                                "Access-Control-Allow-Origin without credentials. "
                                "Attackers can still read non-credentialed API responses."
                            ),
                            evidence=(
                                f"Sent Origin: {origin}\n"
                                f"Access-Control-Allow-Origin: {acao}"
                            ),
                            remediation="Use a strict origin whitelist instead of reflecting back the request Origin.",
                            code_fix=(
                                "ALLOWED_ORIGINS = ['https://app.yourdomain.com']\n"
                                "# validate request origin against this list before echoing it"
                            ),
                            reference="https://portswigger.net/web-security/cors",
                            cvss=7.5,
                        ))

                # 3. null origin allowed with credentials
                if origin == "null" and "null" in acao and acac.lower() == "true":
                    findings.append(Finding(
                        title="CORS Allows 'null' Origin with Credentials",
                        severity=Severity.HIGH,
                        description=(
                            "The server accepts 'null' as a CORS origin with credentials enabled. "
                            "Sandboxed iframes and local file requests use origin 'null', "
                            "making this exploitable from a malicious HTML file."
                        ),
                        evidence=(
                            f"Access-Control-Allow-Origin: null\n"
                            f"Access-Control-Allow-Credentials: true"
                        ),
                        remediation="Never allow 'null' origin in CORS configuration.",
                        code_fix="Remove 'null' from allowed CORS origins entirely.",
                        reference="https://portswigger.net/web-security/cors/lab-null-origin-whitelisted-with-credentials",
                        cvss=8.1,
                    ))

            except Exception:
                continue

    return findings
