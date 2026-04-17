"""
HTTP Security Headers Module
Checks for presence and correctness of all important security headers.
Learned from: Greaper (best structure), Wapiti (CSP), GSEC (full list)
"""

from __future__ import annotations
from typing import List
import httpx
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

# (header_name, severity_if_missing, recommended_value, description, remediation, code_fix, reference)
HEADERS_DB = [
    (
        "Strict-Transport-Security",
        Severity.HIGH,
        "max-age=31536000; includeSubDomains; preload",
        "HSTS forces browsers to use HTTPS, preventing protocol downgrade attacks and cookie hijacking.",
        "Add the Strict-Transport-Security header to all HTTPS responses. Set max-age to at least 1 year.",
        'response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"',
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
    ),
    (
        "Content-Security-Policy",
        Severity.HIGH,
        "default-src 'self'",
        "CSP prevents XSS attacks by controlling which resources the browser is allowed to load.",
        "Define a Content-Security-Policy header. Start with 'default-src self' and expand as needed.",
        'response.headers["Content-Security-Policy"] = "default-src \'self\'; script-src \'self\'"',
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
    ),
    (
        "X-Frame-Options",
        Severity.MEDIUM,
        "SAMEORIGIN",
        "Prevents your site from being embedded in iframes, protecting against clickjacking attacks.",
        "Set X-Frame-Options to DENY or SAMEORIGIN. Or use CSP frame-ancestors directive instead.",
        'response.headers["X-Frame-Options"] = "SAMEORIGIN"',
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
    ),
    (
        "X-Content-Type-Options",
        Severity.MEDIUM,
        "nosniff",
        "Prevents browsers from MIME-sniffing the content type, reducing risk of drive-by downloads.",
        "Always set X-Content-Type-Options: nosniff on all responses.",
        'response.headers["X-Content-Type-Options"] = "nosniff"',
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
    ),
    (
        "Referrer-Policy",
        Severity.LOW,
        "strict-origin-when-cross-origin",
        "Controls how much referrer information is included in requests, protecting user privacy.",
        "Set Referrer-Policy to strict-origin-when-cross-origin or no-referrer.",
        'response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"',
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
    ),
    (
        "Permissions-Policy",
        Severity.LOW,
        "geolocation=(), microphone=(), camera=()",
        "Controls which browser features (camera, mic, geolocation) can be used by your site.",
        "Add a Permissions-Policy header to restrict access to sensitive browser APIs.",
        'response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"',
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
    ),
    (
        "Cross-Origin-Opener-Policy",
        Severity.LOW,
        "same-origin",
        "Isolates your browsing context to prevent cross-origin attacks like Spectre.",
        "Set Cross-Origin-Opener-Policy to same-origin for most applications.",
        'response.headers["Cross-Origin-Opener-Policy"] = "same-origin"',
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy",
    ),
    (
        "Cross-Origin-Resource-Policy",
        Severity.LOW,
        "same-origin",
        "Prevents other origins from reading your resources, protecting against Spectre-like attacks.",
        "Set Cross-Origin-Resource-Policy to same-origin or same-site.",
        'response.headers["Cross-Origin-Resource-Policy"] = "same-origin"',
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy",
    ),
]

# Dangerous headers that should NOT be present (info leak)
DANGEROUS_HEADERS = [
    ("Server",         "Exposes server software and version, aiding fingerprinting by attackers."),
    ("X-Powered-By",  "Reveals backend technology (e.g. PHP/7.4.0), making targeted attacks easier."),
    ("X-AspNet-Version", "Reveals ASP.NET version, which attackers use to look up known exploits."),
    ("X-Generator",   "Reveals CMS or framework, enabling targeted attacks."),
]


def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []

    try:
        with get_client(timeout=timeout) as client:
            resp = client.get(url)
    except Exception as e:
        return [Finding(
            title="Headers scan failed",
            severity=Severity.INFO,
            description=str(e),
            module="headers",
        )]

    resp_headers = {k.lower(): v for k, v in resp.headers.items()}

    # Check required security headers
    for (name, severity, recommended, description, remediation, code_fix, reference) in HEADERS_DB:
        if name.lower() not in resp_headers:
            findings.append(Finding(
                title=f"Missing Security Header: {name}",
                severity=severity,
                description=description,
                evidence=f"Header '{name}' not present in response from {url}",
                remediation=remediation,
                code_fix=code_fix,
                reference=reference,
            ))
        else:
            # Header present — check value quality
            val = resp_headers[name.lower()]
            if name == "Strict-Transport-Security" and "max-age=" not in val.lower():
                findings.append(Finding(
                    title="HSTS Header has Invalid Value",
                    severity=Severity.MEDIUM,
                    description="The Strict-Transport-Security header is present but missing 'max-age'.",
                    evidence=f"Actual value: {val}",
                    remediation="Ensure max-age is set to at least 31536000 (1 year).",
                    code_fix='Strict-Transport-Security: max-age=31536000; includeSubDomains',
                    reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
                ))
            if name == "X-Frame-Options" and val.upper() not in ("DENY", "SAMEORIGIN"):
                findings.append(Finding(
                    title="X-Frame-Options has Weak Value",
                    severity=Severity.MEDIUM,
                    description="X-Frame-Options is set but with an invalid value. Only DENY or SAMEORIGIN are valid.",
                    evidence=f"Actual value: {val}",
                    remediation="Set X-Frame-Options to DENY or SAMEORIGIN.",
                    code_fix="X-Frame-Options: SAMEORIGIN",
                    reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
                ))
            if name == "X-Content-Type-Options" and "nosniff" not in val.lower():
                findings.append(Finding(
                    title="X-Content-Type-Options has Weak Value",
                    severity=Severity.MEDIUM,
                    description="X-Content-Type-Options must be set to exactly 'nosniff'.",
                    evidence=f"Actual value: {val}",
                    remediation="Set the value to exactly 'nosniff'.",
                    code_fix="X-Content-Type-Options: nosniff",
                    reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
                ))

    # Check for dangerous headers that leak info
    for (name, description) in DANGEROUS_HEADERS:
        if name.lower() in resp_headers:
            val = resp_headers[name.lower()]
            findings.append(Finding(
                title=f"Information Disclosure via '{name}' Header",
                severity=Severity.LOW,
                description=description,
                evidence=f"{name}: {val}",
                remediation=f"Remove or obscure the '{name}' response header in your web server config.",
                code_fix=(
                    "# Nginx: server_tokens off;\n"
                    "# Apache: ServerTokens Prod\n"
                    "# Express: app.disable('x-powered-by')"
                ),
                reference="https://owasp.org/www-project-secure-headers/",
            ))

    return findings
