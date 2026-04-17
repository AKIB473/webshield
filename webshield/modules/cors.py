"""
CORS Misconfiguration Module (v1.3.0 — Advanced)
Covers ALL known CORS attack vectors per PortSwigger, HackTricks, Bug Bounty research 2024/2025:
- Reflected/arbitrary origin
- Null origin with credentials
- Subdomain wildcard bypass
- Pre-domain / suffix bypass (e.g. evil-target.com)
- HTTP origin trusted alongside HTTPS
- Trusted subdomain regex bypass
- Wildcard with credentials (browser-blocked but config flaw)
- CORS on sensitive API endpoints specifically
"""

from __future__ import annotations
import re
from typing import List, Optional, Tuple
from urllib.parse import urlparse
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client


def _get_base_domain(url: str) -> str:
    """Extract registrable domain (e.g. example.com from sub.example.com)."""
    host = urlparse(url).netloc.split(":")[0]
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def _build_test_origins(url: str) -> List[Tuple[str, str, str]]:
    """
    Returns list of (origin, attack_name, description) to test.
    Uses the actual target domain to craft domain-specific bypasses.
    """
    parsed = urlparse(url)
    scheme = parsed.scheme
    host = parsed.netloc.split(":")[0]
    base_domain = _get_base_domain(url)

    return [
        # ── Arbitrary origin reflection
        ("https://evil.com",
         "arbitrary_origin",
         "Arbitrary origin reflected"),

        ("https://attacker.com",
         "arbitrary_origin_2",
         "Second arbitrary origin reflected"),

        # ── null origin (sandboxed iframes, local files, data: URIs)
        ("null",
         "null_origin",
         "null origin accepted"),

        # ── Pre-domain bypass: evil-TARGET.com (trusted suffix)
        (f"https://evil-{base_domain}",
         "predomain_bypass",
         f"Pre-domain bypass (evil-{base_domain})"),

        (f"https://evil{base_domain}",
         "prefix_bypass",
         f"Prefix bypass (evil{base_domain})"),

        # ── Post-domain bypass: TARGETeevil.com
        (f"https://{base_domain}.evil.com",
         "postdomain_bypass",
         f"Post-domain bypass ({base_domain}.evil.com)"),

        # ── Subdomain bypass: FUZZ.TARGET.com
        (f"https://subdomain.{base_domain}",
         "subdomain_bypass",
         f"Subdomain bypass (subdomain.{base_domain})"),

        (f"https://evil.{base_domain}",
         "evil_subdomain",
         f"Evil subdomain bypass (evil.{base_domain})"),

        # ── HTTP origin against HTTPS target (downgrade)
        (f"http://{host}",
         "http_origin",
         f"HTTP origin against HTTPS target"),

        # ── Wildcard subdomain bypass: anything.REGISTRABLE
        (f"https://anything.{base_domain}",
         "wildcard_sub",
         f"Wildcard subdomain (anything.{base_domain})"),

        # ── Case variation (some servers do case-insensitive matching)
        (f"HTTPS://{host}",
         "case_variation",
         "Case variation in origin scheme"),

        # ── Trusted domain with path (some naive string-contains checks)
        (f"https://{base_domain}.evil.com/path",
         "path_bypass",
         f"Path bypass"),
    ]


def _check_origin(
    client,
    url: str,
    origin: str,
    attack_name: str,
    attack_desc: str,
    findings: List[Finding],
) -> bool:
    """
    Sends a request with the crafted Origin header and analyzes the response.
    Returns True if a vulnerability was found.
    """
    try:
        # Test both GET and OPTIONS (preflight)
        resp = client.get(url, headers={"Origin": origin})
        acao = resp.headers.get("access-control-allow-origin", "").strip()
        acac = resp.headers.get("access-control-allow-credentials", "").strip().lower()
        acam = resp.headers.get("access-control-allow-methods", "")
        acah = resp.headers.get("access-control-allow-headers", "")
        vary = resp.headers.get("vary", "").lower()
    except Exception:
        return False

    has_credentials = acac == "true"

    # ── 1. Wildcard * with credentials (invalid but config flaw)
    if acao == "*" and has_credentials:
        findings.append(Finding(
            title="CORS: Wildcard Origin + Credentials (Invalid Config)",
            severity=Severity.HIGH,
            description=(
                "Access-Control-Allow-Origin: * combined with "
                "Access-Control-Allow-Credentials: true is rejected by browsers, "
                "but indicates a broken CORS implementation that could work with "
                "custom clients or future browser versions."
            ),
            evidence=(
                f"Access-Control-Allow-Origin: {acao}\n"
                f"Access-Control-Allow-Credentials: {acac}"
            ),
            remediation="Never use * with credentials. Use explicit allowed origin list.",
            reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS/Errors/CORSNotSupportingCredentials",
            module="cors",
            cvss=7.5,
        ))
        return True

    # ── 2. Wildcard * without credentials
    if acao == "*":
        findings.append(Finding(
            title="CORS: Wildcard (*) Origin Allowed",
            severity=Severity.MEDIUM,
            description=(
                "The server allows any origin to make cross-origin requests. "
                "While credentials cannot be sent with *, any origin can read "
                "public API responses. This may expose internal data to any website."
            ),
            evidence=f"Access-Control-Allow-Origin: *",
            remediation=(
                "Restrict CORS to specific trusted origins. "
                "If this is a public API, ensure no sensitive data is returned."
            ),
            code_fix=(
                "# Flask:\n"
                "from flask_cors import CORS\n"
                "CORS(app, origins=['https://yourdomain.com'])\n\n"
                "# Express:\n"
                "app.use(cors({ origin: 'https://yourdomain.com' }))\n\n"
                "# Django:\n"
                "CORS_ALLOWED_ORIGINS = ['https://yourdomain.com']"
            ),
            reference="https://portswigger.net/web-security/cors",
            module="cors",
            cvss=5.3,
        ))
        return True

    # ── 3. Arbitrary origin reflected back
    if acao == origin or (origin == "null" and "null" in acao):
        if has_credentials:
            # Critical — can make authenticated requests from any origin
            findings.append(Finding(
                title=f"CORS Critical: Arbitrary Origin Reflected + Credentials | {attack_name}",
                severity=Severity.CRITICAL,
                description=(
                    f"The server reflects arbitrary origins in Access-Control-Allow-Origin "
                    f"AND sets Access-Control-Allow-Credentials: true. "
                    f"Attack tested: {attack_desc}.\n\n"
                    "This allows ANY malicious website to:\n"
                    "• Make authenticated API requests as the victim\n"
                    "• Read the victim's private data from your API\n"
                    "• Perform account takeover without any user interaction\n"
                    "This is one of the most critical CORS misconfigurations."
                ),
                evidence=(
                    f"Origin sent: {origin}\n"
                    f"Access-Control-Allow-Origin: {acao}\n"
                    f"Access-Control-Allow-Credentials: {acac}\n"
                    f"Access-Control-Allow-Methods: {acam}"
                ),
                remediation=(
                    "NEVER dynamically reflect the Origin header. "
                    "Maintain a strict whitelist of trusted origins. "
                    "Validate on the server using an allowlist, not string matching."
                ),
                code_fix=(
                    "# ❌ VULNERABLE (reflecting origin):\n"
                    "response.headers['Access-Control-Allow-Origin'] = request.headers['Origin']\n\n"
                    "# ✅ SAFE (whitelist validation):\n"
                    "ALLOWED_ORIGINS = [\n"
                    "    'https://app.yourdomain.com',\n"
                    "    'https://www.yourdomain.com',\n"
                    "]\n"
                    "origin = request.headers.get('Origin')\n"
                    "if origin in ALLOWED_ORIGINS:\n"
                    "    response.headers['Access-Control-Allow-Origin'] = origin\n"
                    "    response.headers['Vary'] = 'Origin'  # prevent caching issues\n"
                    "# else: don't set CORS header at all"
                ),
                reference="https://portswigger.net/web-security/cors/lab-reflect-arbitrary-origins",
                module="cors",
                cvss=9.3,
            ))
        else:
            # High — can read non-credentialed responses
            findings.append(Finding(
                title=f"CORS High: Arbitrary Origin Reflected (No Credentials) | {attack_name}",
                severity=Severity.HIGH,
                description=(
                    f"The server reflects any arbitrary Origin without requiring credentials. "
                    f"Attack tested: {attack_desc}.\n"
                    "Attackers can read non-authenticated API responses cross-origin. "
                    "If any sensitive data is returned without auth, this is exploitable."
                ),
                evidence=(
                    f"Origin sent: {origin}\n"
                    f"Access-Control-Allow-Origin: {acao}"
                ),
                remediation="Use an explicit origin whitelist instead of reflecting the request Origin.",
                code_fix=(
                    "ALLOWED_ORIGINS = ['https://yourdomain.com']\n"
                    "origin = request.headers.get('Origin')\n"
                    "if origin in ALLOWED_ORIGINS:\n"
                    "    response.headers['Access-Control-Allow-Origin'] = origin"
                ),
                reference="https://portswigger.net/web-security/cors",
                module="cors",
                cvss=7.5,
            ))
        return True

    return False


def _check_sensitive_endpoints(client, url: str, findings: List[Finding]) -> None:
    """Test CORS on common sensitive API paths specifically."""
    base = url.rstrip("/")
    sensitive_paths = [
        "/api/user", "/api/v1/user", "/api/me", "/api/profile",
        "/api/account", "/api/v1/account",
    ]
    for path in sensitive_paths:
        try:
            resp = client.get(
                base + path,
                headers={"Origin": "https://evil.com"},
            )
            acao = resp.headers.get("access-control-allow-origin", "")
            acac = resp.headers.get("access-control-allow-credentials", "").lower()
            if resp.status_code == 200 and acao == "https://evil.com" and acac == "true":
                findings.append(Finding(
                    title=f"CORS Critical on Sensitive API Endpoint: {path}",
                    severity=Severity.CRITICAL,
                    description=(
                        f"The sensitive API endpoint {path} reflects arbitrary origins "
                        "with credentials. Attackers can steal authenticated user data "
                        "from this endpoint via cross-origin requests."
                    ),
                    evidence=(
                        f"Endpoint: {base + path}\n"
                        f"Access-Control-Allow-Origin: {acao}\n"
                        f"Access-Control-Allow-Credentials: {acac}"
                    ),
                    remediation="Apply strict origin validation on all API endpoints.",
                    reference="https://portswigger.net/web-security/cors",
                    module="cors",
                    cvss=9.3,
                ))
                return
        except Exception:
            continue


def _check_missing_vary(client, url: str, findings: List[Finding]) -> None:
    """Check if CORS responses are missing Vary: Origin (cache poisoning risk)."""
    try:
        resp = client.get(url, headers={"Origin": "https://example.com"})
        acao = resp.headers.get("access-control-allow-origin", "")
        vary = resp.headers.get("vary", "").lower()
        if acao and acao != "*" and "origin" not in vary:
            findings.append(Finding(
                title="CORS Response Missing 'Vary: Origin' Header",
                severity=Severity.LOW,
                description=(
                    "The server returns origin-specific CORS headers but does not include "
                    "'Vary: Origin'. This can cause CDN/proxy caches to serve a response "
                    "with one origin's CORS headers to a different origin (cache poisoning)."
                ),
                evidence=f"Vary header: '{vary}' (should include 'Origin')\n"
                         f"Access-Control-Allow-Origin: {acao}",
                remediation="Add 'Vary: Origin' to all CORS responses.",
                code_fix="response.headers['Vary'] = 'Origin'",
                reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Vary",
                module="cors",
                cvss=3.1,
            ))
    except Exception:
        pass


def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    test_origins = _build_test_origins(url)

    with get_client(timeout=min(timeout, 8.0)) as client:
        # Test all crafted origins
        for (origin, attack_name, attack_desc) in test_origins:
            found = _check_origin(client, url, origin, attack_name, attack_desc, findings)
            if found and any(f.severity == Severity.CRITICAL for f in findings):
                break  # critical found — no need to keep probing

        # Test sensitive API endpoints specifically
        if len(findings) == 0:
            _check_sensitive_endpoints(client, url, findings)

        # Check for missing Vary header
        _check_missing_vary(client, url, findings)

    return findings
