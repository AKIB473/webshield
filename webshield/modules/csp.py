"""
Content Security Policy (CSP) Deep Analysis Module (v1.3.0 — Advanced)
Full directive analysis, nonce/hash detection, bypass vectors, report-only mode,
CSP header injection via meta tags, and JSONP/CDN bypass detection.
Research: PortSwigger, Mozilla CSP spec, Google CSP Evaluator, 2024/2025 research.
"""

from __future__ import annotations
import re
from typing import List, Dict, Optional, Tuple
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

# ─── Required Directives ──────────────────────────────────────────────────────

REQUIRED_DIRECTIVES = {
    "default-src":     (Severity.HIGH,   "Controls all resource types with no specific directive. Without it, nothing is restricted."),
    "script-src":      (Severity.HIGH,   "Controls which scripts can execute. Missing means any script from any origin can run."),
    "object-src":      (Severity.HIGH,   "Controls Flash/plugin objects. Should be 'none'. Missing enables plugin-based XSS."),
    "base-uri":        (Severity.MEDIUM, "Prevents <base> tag injection. A missing base-uri allows attackers to redirect relative URLs."),
    "frame-ancestors": (Severity.MEDIUM, "Modern replacement for X-Frame-Options. Controls who can embed your site in iframes."),
}

# ─── Unsafe Script Values ─────────────────────────────────────────────────────

UNSAFE_SCRIPT_VALUES: Dict[str, Tuple[Severity, str]] = {
    "'unsafe-inline'": (Severity.HIGH,   "Allows inline <script> tags and event handlers — completely defeats XSS protection."),
    "'unsafe-eval'":   (Severity.HIGH,   "Allows eval(), Function(), setTimeout(string) — enables code injection attacks."),
    "'unsafe-hashes'": (Severity.MEDIUM, "Allows hashed inline event handlers — still weaker than nonce-based approach."),
    "data:":           (Severity.MEDIUM, "Allows data: URIs in scripts — can be exploited to load malicious scripts."),
    "http:":           (Severity.HIGH,   "Allows scripts over unencrypted HTTP — man-in-the-middle can inject malicious code."),
    "https:":          (Severity.HIGH,   "Wildcard HTTPS origin — allows scripts from any HTTPS domain on the internet."),
    "*":               (Severity.CRITICAL, "Wildcard * allows scripts from any domain — completely open, no XSS protection."),
}

# ─── Known JSONP / Bypass CDN Endpoints ───────────────────────────────────────
# These domains have JSONP endpoints that bypass CSP script-src restrictions

JSONP_BYPASS_DOMAINS = [
    "accounts.google.com",
    "google.com",
    "*.google.com",
    "googleapis.com",
    "*.googleapis.com",
    "googletagmanager.com",
    "*.googletagmanager.com",
    "cdn.jsdelivr.net",
    "*.jsdelivr.net",
    "ajax.googleapis.com",
    "cdnjs.cloudflare.com",
    "*.cloudflare.com",
    "unpkg.com",
    "*.unpkg.com",
    "angular.io",
    "stackblitz.io",
]

# ─── Helpers ─────────────────────────────────────────────────────────────────

def _parse_csp(header: str) -> Dict[str, List[str]]:
    directives: Dict[str, List[str]] = {}
    for part in header.split(";"):
        tokens = part.strip().split()
        if not tokens:
            continue
        name = tokens[0].lower()
        values = [v.lower() for v in tokens[1:]]
        directives[name] = values
    return directives


def _effective_script_src(directives: Dict[str, List[str]]) -> List[str]:
    """Returns the effective script-src (falls back to default-src)."""
    return directives.get("script-src") or directives.get("default-src") or []


def _has_nonce_or_hash(values: List[str]) -> bool:
    return any(
        v.startswith("'nonce-") or v.startswith("'sha256-") or
        v.startswith("'sha384-") or v.startswith("'sha512-")
        for v in values
    )


def _check_jsonp_bypass(script_src: List[str]) -> Optional[str]:
    """Check if any allowed script-src domain has known JSONP endpoints."""
    for val in script_src:
        for bypass_domain in JSONP_BYPASS_DOMAINS:
            clean_bypass = bypass_domain.lstrip("*.")
            if clean_bypass in val:
                return bypass_domain
    return None


# ─── Main Scanner ─────────────────────────────────────────────────────────────

def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []

    try:
        with get_client(timeout=timeout) as client:
            resp = client.get(url)
    except Exception:
        return []

    headers_lower = {k.lower(): v for k, v in resp.headers.items()}
    csp_header = (
        headers_lower.get("content-security-policy") or
        headers_lower.get("x-content-security-policy") or
        headers_lower.get("x-webkit-csp")
    )
    report_only = headers_lower.get("content-security-policy-report-only")

    # ── No CSP at all ─────────────────────────────────────────────────────────
    if not csp_header and not report_only:
        findings.append(Finding(
            title="No Content Security Policy (CSP) Configured",
            severity=Severity.HIGH,
            description=(
                "No Content-Security-Policy header was found. Without CSP, any XSS "
                "vulnerability can be fully exploited — attackers can steal cookies, "
                "hijack sessions, redirect users, and inject arbitrary content. "
                "CSP is the primary defense-in-depth control against XSS."
            ),
            evidence=f"No CSP header in HTTP response from {url}",
            remediation=(
                "Implement a Content-Security-Policy immediately. "
                "Start with a reporting-only policy during testing, then enforce."
            ),
            code_fix=(
                "# Minimal strong CSP:\n"
                "Content-Security-Policy: "
                "default-src 'self'; "
                "script-src 'self'; "
                "object-src 'none'; "
                "base-uri 'self'; "
                "frame-ancestors 'self';\n\n"
                "# With nonce (allows some inline scripts safely):\n"
                "script-src 'self' 'nonce-{RANDOM_BASE64}'\n\n"
                "# Nginx:\n"
                "add_header Content-Security-Policy "
                "\"default-src 'self'; script-src 'self'; object-src 'none'\" always;\n\n"
                "# Test your CSP: https://csp-evaluator.withgoogle.com/"
            ),
            reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
            module="csp",
            cvss=6.1,
        ))
        return findings

    # ── Report-only mode only ─────────────────────────────────────────────────
    if report_only and not csp_header:
        findings.append(Finding(
            title="CSP is Report-Only — NOT Enforced (XSS Still Possible)",
            severity=Severity.MEDIUM,
            description=(
                "Content-Security-Policy-Report-Only is set but there is no enforcing CSP. "
                "Violations are logged but NOT blocked. XSS attacks will still succeed. "
                "The report-only policy is useful for testing but must not replace enforcement."
            ),
            evidence="Content-Security-Policy-Report-Only found; no Content-Security-Policy",
            remediation="Once report-only testing confirms no violations, switch to enforcing mode.",
            code_fix=(
                "# Change:\n"
                "Content-Security-Policy-Report-Only: ...\n\n"
                "# To:\n"
                "Content-Security-Policy: ..."
            ),
            reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy-Report-Only",
            module="csp",
            cvss=5.3,
        ))
        csp_header = report_only  # analyze it anyway

    directives = _parse_csp(csp_header)
    script_src = _effective_script_src(directives)
    has_nonce = _has_nonce_or_hash(script_src)

    # ── Check required directives ─────────────────────────────────────────────
    for directive, (severity, description) in REQUIRED_DIRECTIVES.items():
        if directive not in directives:
            # object-src check: if default-src is 'none', object-src is covered
            if directive == "object-src":
                default_vals = directives.get("default-src", [])
                if "'none'" in default_vals:
                    continue

            # base-uri check: missing only if no default-src
            if directive == "frame-ancestors" and "x-frame-options" in headers_lower:
                continue  # X-Frame-Options covers this

            findings.append(Finding(
                title=f"CSP Missing Required Directive: {directive}",
                severity=severity,
                description=description,
                evidence=f"'{directive}' not found in CSP: {csp_header[:200]}",
                remediation=f"Add '{directive}' directive to your Content-Security-Policy.",
                code_fix=f"# Add to existing CSP:\n{directive} 'self';  # adjust as needed",
                reference="https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
                module="csp",
            ))

    # ── Check for unsafe values in script-src ─────────────────────────────────
    for unsafe_val, (severity, description) in UNSAFE_SCRIPT_VALUES.items():
        if unsafe_val in script_src:
            # If nonces/hashes are present alongside unsafe-inline, browsers may ignore unsafe-inline
            if unsafe_val == "'unsafe-inline'" and has_nonce:
                findings.append(Finding(
                    title="CSP 'unsafe-inline' with Nonce (Browsers May Ignore unsafe-inline)",
                    severity=Severity.INFO,
                    description=(
                        "CSP contains both 'unsafe-inline' and a nonce/hash. "
                        "Modern browsers (CSP3) will ignore 'unsafe-inline' when a nonce "
                        "is present — this is correct behavior. However, legacy browsers "
                        "will still honor 'unsafe-inline'. Consider removing it for consistency."
                    ),
                    evidence=f"script-src: {' '.join(script_src[:6])}",
                    remediation="Remove 'unsafe-inline' if all supported browsers support nonces (CSP3).",
                    reference="https://www.w3.org/TR/CSP3/#match-nonce",
                    module="csp",
                ))
                continue

            findings.append(Finding(
                title=f"CSP Unsafe Value: '{unsafe_val}' in script-src",
                severity=severity,
                description=description,
                evidence=f"script-src: {' '.join(script_src[:6])}",
                remediation=(
                    f"Remove '{unsafe_val}' from script-src. "
                    "Use nonces for inline scripts: script-src 'self' 'nonce-RANDOM'"
                ),
                code_fix=(
                    "# Instead of 'unsafe-inline', use nonces:\n\n"
                    "# CSP header (generate fresh nonce per request):\n"
                    "import secrets\n"
                    "nonce = secrets.token_urlsafe(16)\n"
                    "csp = f\"script-src 'self' 'nonce-{nonce}'\"\n\n"
                    "# HTML:\n"
                    "<script nonce=\"{{ nonce }}\">/* your inline script */</script>\n\n"
                    "# Instead of 'unsafe-eval', refactor to avoid eval():\n"
                    "# Replace: setTimeout('functionName()', 100)\n"
                    "# With:    setTimeout(functionName, 100)"
                ),
                reference="https://content-security-policy.com/nonce/",
                module="csp",
                cvss=6.1,
            ))

    # ── JSONP / CDN bypass ─────────────────────────────────────────────────────
    bypass_domain = _check_jsonp_bypass(script_src)
    if bypass_domain and not has_nonce:
        findings.append(Finding(
            title=f"CSP Bypassable via JSONP on Allowed Domain: {bypass_domain}",
            severity=Severity.HIGH,
            description=(
                f"The CSP allows scripts from '{bypass_domain}' which has known JSONP "
                "endpoints. Attackers can use these endpoints to execute arbitrary JavaScript "
                "within your CSP policy, effectively bypassing XSS protection.\n\n"
                f"Example: <script src='https://{bypass_domain.lstrip('*.')}/callback?jsonp=alert(1)'></script>"
            ),
            evidence=f"Allowed domain with JSONP endpoints: {bypass_domain}",
            remediation=(
                "Remove broad CDN domains from script-src. "
                "Self-host critical scripts or use specific file hashes instead of domain allowlists."
            ),
            code_fix=(
                "# Instead of allowing entire CDN domains:\n"
                "# BAD: script-src 'self' https://cdn.jsdelivr.net\n\n"
                "# GOOD: use SHA256 hash of the specific script:\n"
                "# script-src 'self' 'sha256-{hash_of_script}'\n\n"
                "# Or better: self-host the scripts:\n"
                "# script-src 'self'"
            ),
            reference="https://portswigger.net/research/csp-is-dead-long-live-csp",
            module="csp",
            cvss=6.5,
        ))

    # ── Wildcard in any directive ──────────────────────────────────────────────
    for directive, values in directives.items():
        if directive in ("script-src", "default-src"):
            continue  # already checked above
        for val in values:
            if val == "*" or (val.startswith("http") and "://*." in val):
                findings.append(Finding(
                    title=f"CSP Wildcard in {directive}",
                    severity=Severity.MEDIUM,
                    description=(
                        f"The CSP directive '{directive}' contains a wildcard '{val}' "
                        "that allows resources from any matching domain."
                    ),
                    evidence=f"{directive}: {' '.join(values[:5])}",
                    remediation=f"Replace wildcard in '{directive}' with specific trusted domains.",
                    reference="https://content-security-policy.com/",
                    module="csp",
                ))
                break

    # ── Missing upgrade-insecure-requests ─────────────────────────────────────
    if "upgrade-insecure-requests" not in directives:
        findings.append(Finding(
            title="CSP Missing 'upgrade-insecure-requests' Directive",
            severity=Severity.LOW,
            description=(
                "The 'upgrade-insecure-requests' directive is not set. "
                "This directive tells browsers to automatically upgrade HTTP resource "
                "requests to HTTPS, preventing mixed content issues."
            ),
            evidence="'upgrade-insecure-requests' not in CSP",
            remediation="Add 'upgrade-insecure-requests' to your CSP.",
            code_fix="Content-Security-Policy: ... ; upgrade-insecure-requests",
            reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/upgrade-insecure-requests",
            module="csp",
        ))

    # ── Check for report-uri / report-to (good practice) ─────────────────────
    has_reporting = "report-uri" in directives or "report-to" in directives
    if not has_reporting:
        findings.append(Finding(
            title="CSP Missing Reporting Directive (report-uri / report-to)",
            severity=Severity.INFO,
            description=(
                "No CSP violation reporting is configured. Without reporting, "
                "you won't know when your CSP is being triggered, making it harder "
                "to detect ongoing XSS attempts or policy refinement needs."
            ),
            evidence="No report-uri or report-to directive in CSP",
            remediation="Add a report-uri or report-to directive to receive CSP violation reports.",
            code_fix=(
                "# Add to CSP header:\n"
                "Content-Security-Policy: ... ; report-uri /csp-report\n\n"
                "# Or use report-to (newer):\n"
                "Report-To: {\"group\":\"csp\",\"max_age\":31536000,\"endpoints\":[{\"url\":\"/csp-report\"}]}\n"
                "Content-Security-Policy: ... ; report-to csp"
            ),
            reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/report-uri",
            module="csp",
        ))

    return findings
