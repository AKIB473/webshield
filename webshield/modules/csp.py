"""
Content Security Policy (CSP) Deep Analysis Module
Checks each CSP directive for weakness and unsafe values.
Learned from: Wapiti (mod_csp.py — best CSP analysis found), GSEC
"""

from __future__ import annotations
import re
from typing import List, Dict, Optional
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

# Directives that MUST be present in a strong CSP
REQUIRED_DIRECTIVES = {
    "default-src": (Severity.HIGH,   "Controls resources that have no specific directive. Without it, nothing is restricted."),
    "script-src":  (Severity.HIGH,   "Controls which scripts can execute. Missing allows any script from anywhere."),
    "object-src":  (Severity.HIGH,   "Controls Flash/Java plugins. Should be 'none'. Missing allows plugin attacks."),
    "base-uri":    (Severity.MEDIUM, "Prevents base tag injection attacks that redirect relative URLs."),
    "frame-ancestors": (Severity.MEDIUM, "Modern replacement for X-Frame-Options. Controls who can iframe your site."),
}

# Unsafe values for script-src or default-src
UNSAFE_SCRIPT_VALUES = {
    "'unsafe-inline'": (Severity.HIGH,   "Allows inline scripts, completely defeating XSS protection."),
    "'unsafe-eval'":   (Severity.HIGH,   "Allows eval() and similar functions, enabling code injection."),
    "data:":           (Severity.MEDIUM, "Allows data: URIs in scripts, which can be abused for XSS."),
    "*":               (Severity.HIGH,   "Wildcard allows scripts from any domain."),
    "http:":           (Severity.MEDIUM, "Allows loading scripts over insecure HTTP."),
}


def parse_csp(header_value: str) -> Dict[str, List[str]]:
    """Parse a CSP header string into a directive→values dict."""
    directives: Dict[str, List[str]] = {}
    for directive in header_value.split(";"):
        parts = directive.strip().split()
        if not parts:
            continue
        name = parts[0].lower()
        values = [v.lower() for v in parts[1:]]
        directives[name] = values
    return directives


def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []

    try:
        with get_client(timeout=timeout) as client:
            resp = client.get(url)
    except Exception:
        return []

    csp_header = (
        resp.headers.get("content-security-policy") or
        resp.headers.get("Content-Security-Policy")
    )

    if not csp_header:
        findings.append(Finding(
            title="Content Security Policy (CSP) Not Set",
            severity=Severity.HIGH,
            description=(
                "No Content-Security-Policy header found. Without CSP, attackers who "
                "find an XSS vulnerability can inject and run arbitrary scripts, "
                "steal cookies, or redirect users to phishing pages."
            ),
            evidence=f"No CSP header in response from {url}",
            remediation="Implement a Content Security Policy. Start strict and loosen as needed.",
            code_fix=(
                "# Start with a strict policy:\n"
                "Content-Security-Policy: "
                "default-src 'self'; "
                "script-src 'self'; "
                "object-src 'none'; "
                "base-uri 'self'; "
                "frame-ancestors 'self';\n\n"
                "# Nginx:\n"
                "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none'\" always;"
            ),
            reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
            cvss=6.1,
        ))
        return findings

    directives = parse_csp(csp_header)

    # 1. Check required directives are present
    for directive, (severity, description) in REQUIRED_DIRECTIVES.items():
        if directive not in directives:
            # object-src may be covered by default-src
            if directive == "object-src" and "default-src" in directives:
                default_vals = directives["default-src"]
                if "'none'" in default_vals:
                    continue

            findings.append(Finding(
                title=f"CSP Missing Directive: {directive}",
                severity=severity,
                description=description,
                evidence=f"Directive '{directive}' not found in CSP: {csp_header[:150]}",
                remediation=f"Add '{directive}' to your Content-Security-Policy header.",
                code_fix=f"# Add to existing CSP:\n{directive} 'self';   # adjust as needed",
                reference="https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
            ))

    # 2. Check for unsafe values in script-src / default-src
    for directive in ("script-src", "default-src"):
        if directive not in directives:
            continue
        values = directives[directive]
        for unsafe_val, (severity, description) in UNSAFE_SCRIPT_VALUES.items():
            if unsafe_val in values:
                findings.append(Finding(
                    title=f"Unsafe CSP Value '{unsafe_val}' in {directive}",
                    severity=severity,
                    description=description,
                    evidence=f"{directive}: {' '.join(values)}",
                    remediation=(
                        f"Remove '{unsafe_val}' from {directive}. "
                        "Use nonces or hashes for inline scripts instead of 'unsafe-inline'."
                    ),
                    code_fix=(
                        "# Instead of 'unsafe-inline', use nonces:\n"
                        "# In your CSP:\n"
                        "script-src 'self' 'nonce-{random_base64}'\n\n"
                        "# In your HTML:\n"
                        "<script nonce=\"{same_random_base64}\">...</script>"
                    ),
                    reference="https://content-security-policy.com/nonce/",
                    cvss=6.1,
                ))

    # 3. Wildcard domain in sources
    for directive, values in directives.items():
        for val in values:
            if val == "*" or (val.startswith("http") and "*" in val):
                findings.append(Finding(
                    title=f"CSP Wildcard Domain in {directive}",
                    severity=Severity.MEDIUM,
                    description=(
                        f"The directive '{directive}' contains a wildcard that allows "
                        "resources from potentially any domain."
                    ),
                    evidence=f"{directive}: {' '.join(values)}",
                    remediation="Replace wildcards with specific trusted domain names.",
                    reference="https://content-security-policy.com/",
                ))

    # 4. CSP report-only mode (not enforced)
    report_only = resp.headers.get("content-security-policy-report-only")
    if report_only and not csp_header:
        findings.append(Finding(
            title="CSP is in Report-Only Mode (Not Enforced)",
            severity=Severity.MEDIUM,
            description=(
                "Content-Security-Policy-Report-Only is set but no enforcing CSP header exists. "
                "Violations are reported but NOT blocked. XSS attacks will still succeed."
            ),
            evidence="Content-Security-Policy-Report-Only header found, no Content-Security-Policy",
            remediation="Switch from report-only to enforcing mode once you've confirmed no legitimate violations.",
            code_fix="Change 'Content-Security-Policy-Report-Only' to 'Content-Security-Policy'",
            reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy-Report-Only",
        ))

    return findings
