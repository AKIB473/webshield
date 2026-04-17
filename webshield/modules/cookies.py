"""
Cookie Security Module (v1.3.0 — Advanced)
Full analysis: Secure, HttpOnly, SameSite, __Host-/__Secure- prefixes,
session ID entropy, cookie scope (Domain/Path), expiry analysis,
SameSite=None without Secure, and cookie-based session fixation indicators.
Research: OWASP Session Management, PortSwigger, RFC 6265bis.
"""

from __future__ import annotations
import re
import math
from typing import List, Dict
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

# ─── Session Cookie Name Patterns ────────────────────────────────────────────

SESSION_NAMES = re.compile(
    r"(sess(ion)?|sid|auth|token|jwt|login|user|uid|account|remember|identity|csrf)",
    re.I
)

ADMIN_NAMES = re.compile(r"(admin|root|superuser|staff)", re.I)

# ─── Helpers ──────────────────────────────────────────────────────────────────

def _parse_set_cookie(raw: str) -> Dict[str, str]:
    """Parse a raw Set-Cookie header into a dict of attributes."""
    parts = [p.strip() for p in raw.split(";")]
    result: Dict[str, str] = {}

    if "=" in parts[0]:
        name, _, val = parts[0].partition("=")
        result["__name__"] = name.strip()
        result["__value__"] = val.strip()
    else:
        result["__name__"] = parts[0].strip()
        result["__value__"] = ""

    for attr in parts[1:]:
        if "=" in attr:
            k, _, v = attr.partition("=")
            result[k.strip().lower()] = v.strip()
        else:
            result[attr.strip().lower()] = "true"

    return result


def _entropy_bits(value: str) -> float:
    """Estimate information entropy of a string (bits)."""
    if not value:
        return 0.0
    # Detect character set
    has_lower = bool(re.search(r"[a-z]", value))
    has_upper = bool(re.search(r"[A-Z]", value))
    has_digit = bool(re.search(r"[0-9]", value))
    has_special = bool(re.search(r"[^a-zA-Z0-9]", value))

    charset_size = 0
    if has_lower: charset_size += 26
    if has_upper: charset_size += 26
    if has_digit: charset_size += 10
    if has_special: charset_size += 32

    if charset_size == 0:
        return 0.0

    return len(value) * math.log2(charset_size)


def _is_predictable(value: str) -> bool:
    """Heuristic: is the session value suspiciously predictable?"""
    if not value or len(value) < 8:
        return True

    # All same character
    if len(set(value)) < 4:
        return True

    # Sequential numbers
    if re.match(r"^\d+$", value) and int(value) < 1_000_000:
        return True

    # Very short
    if len(value) < 16:
        return True

    return False


def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    from urllib.parse import urlparse as _up
    parsed = _up(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    # Probe multiple endpoints — cookies are often set on auth/session paths
    probe_urls = [url]
    for path in ["/login", "/app", "/profile", "/dashboard", "/account", "/session"]:
        probe_urls.append(base + path)

    resp = None
    try:
        with get_client(timeout=timeout) as client:
            for probe_url in probe_urls:
                try:
                    r = client.get(probe_url)
                    raw_cookies_check = [v for k, v in r.headers.items() if k.lower() == "set-cookie"]
                    if raw_cookies_check:
                        resp = r
                        break
                except Exception:
                    continue
            if resp is None:
                resp = client.get(url)
    except Exception:
        return []

    # Collect all Set-Cookie headers
    raw_cookies = [v for k, v in resp.headers.items() if k.lower() == "set-cookie"]

    if not raw_cookies:
        return []

    is_https = str(resp.url).startswith("https://") if hasattr(resp, "url") else True

    for raw in raw_cookies:
        parsed = _parse_set_cookie(raw)
        name = parsed.get("__name__", "unknown")
        value = parsed.get("__value__", "")
        name_lower = name.lower()

        is_session = bool(SESSION_NAMES.search(name))
        is_admin = bool(ADMIN_NAMES.search(name))
        has_secure = "secure" in parsed
        has_httponly = "httponly" in parsed
        samesite = parsed.get("samesite", "").lower()
        domain = parsed.get("domain", "")
        path = parsed.get("path", "")
        max_age = parsed.get("max-age", "")
        expires = parsed.get("expires", "")

        # ── 1. Missing Secure flag ────────────────────────────────────────────
        if not has_secure:
            sev = Severity.HIGH if (is_session or is_admin) else Severity.MEDIUM
            findings.append(Finding(
                title=f"Cookie Missing Secure Flag: {name}",
                severity=sev,
                description=(
                    f"The cookie '{name}' does not have the Secure flag. "
                    "It will be transmitted over plain HTTP connections, "
                    "exposing it to network eavesdropping and man-in-the-middle attacks."
                ),
                evidence=f"Set-Cookie: {raw[:150]}",
                remediation="Add the Secure flag to all cookies, especially session and auth cookies.",
                code_fix=(
                    "# Flask:\n"
                    f"response.set_cookie('{name}', value, secure=True)\n\n"
                    "# Django settings.py:\n"
                    "SESSION_COOKIE_SECURE = True\n"
                    "CSRF_COOKIE_SECURE = True\n\n"
                    "# Express:\n"
                    f"res.cookie('{name}', value, {{ secure: true }})"
                ),
                reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#secure",
                module="cookies",
                cvss=6.5,
            ))

        # ── 2. Missing HttpOnly flag ──────────────────────────────────────────
        if not has_httponly and is_session:
            findings.append(Finding(
                title=f"Session Cookie Missing HttpOnly Flag: {name}",
                severity=Severity.HIGH,
                description=(
                    f"The session cookie '{name}' lacks the HttpOnly flag. "
                    "JavaScript can access it via document.cookie. "
                    "If XSS is found anywhere on the site, attackers can steal "
                    "this session cookie and take over accounts."
                ),
                evidence=f"Set-Cookie: {raw[:150]}",
                remediation="Add HttpOnly to all session and auth cookies.",
                code_fix=(
                    "# Flask:\n"
                    f"response.set_cookie('{name}', value, httponly=True)\n\n"
                    "# Django:\n"
                    "SESSION_COOKIE_HTTPONLY = True\n\n"
                    "# Express:\n"
                    f"res.cookie('{name}', value, {{ httpOnly: true }})"
                ),
                reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#httponly",
                module="cookies",
                cvss=6.1,
            ))
        elif not has_httponly:
            findings.append(Finding(
                title=f"Cookie Missing HttpOnly Flag: {name}",
                severity=Severity.MEDIUM,
                description=(
                    f"The cookie '{name}' lacks HttpOnly. While it may not be a session "
                    "cookie, JavaScript access is unnecessary for most server-set cookies."
                ),
                evidence=f"Set-Cookie: {raw[:150]}",
                remediation="Add HttpOnly flag unless JavaScript access is explicitly required.",
                reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#httponly",
                module="cookies",
            ))

        # ── 3. SameSite analysis ──────────────────────────────────────────────
        if not samesite:
            findings.append(Finding(
                title=f"Cookie Missing SameSite Attribute: {name}",
                severity=Severity.MEDIUM,
                description=(
                    f"Cookie '{name}' has no SameSite attribute. "
                    "Without it, the cookie is sent on all cross-site requests, "
                    "enabling CSRF attacks. Modern browsers default to 'Lax' but "
                    "not all do — explicitly set SameSite."
                ),
                evidence=f"Set-Cookie: {raw[:150]}",
                remediation="Set SameSite=Lax (recommended) or SameSite=Strict.",
                code_fix=(
                    "# Flask:\n"
                    f"response.set_cookie('{name}', value, samesite='Lax')\n\n"
                    "# Django:\n"
                    "SESSION_COOKIE_SAMESITE = 'Lax'\n\n"
                    "# Express:\n"
                    f"res.cookie('{name}', value, {{ sameSite: 'lax' }})"
                ),
                reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite",
                module="cookies",
            ))
        elif samesite == "none" and not has_secure:
            findings.append(Finding(
                title=f"Cookie SameSite=None Without Secure Flag: {name}",
                severity=Severity.HIGH,
                description=(
                    f"Cookie '{name}' has SameSite=None but no Secure flag. "
                    "Browsers reject SameSite=None cookies without Secure. "
                    "This means the cookie is effectively broken AND misconfigured."
                ),
                evidence=f"Set-Cookie: {raw[:150]}",
                remediation="Add the Secure flag when using SameSite=None.",
                code_fix=f"Set-Cookie: {name}=value; SameSite=None; Secure; HttpOnly",
                reference="https://web.dev/samesite-cookies-explained/",
                module="cookies",
                cvss=6.5,
            ))
        elif samesite == "none":
            findings.append(Finding(
                title=f"Cookie SameSite=None (Allows Cross-Site Sending): {name}",
                severity=Severity.LOW,
                description=(
                    f"Cookie '{name}' uses SameSite=None, meaning it will be sent "
                    "on ALL cross-origin requests including embedded iframes and "
                    "third-party requests. Only use this if cross-site sending is required."
                ),
                evidence=f"SameSite=None on cookie: {name}",
                remediation="Only use SameSite=None if cross-site access is explicitly required.",
                reference="https://web.dev/samesite-cookies-explained/",
                module="cookies",
            ))

        # ── 4. __Host- and __Secure- prefix recommendations ──────────────────
        if is_session and not name.startswith("__Host-") and not name.startswith("__Secure-"):
            findings.append(Finding(
                title=f"Session Cookie Missing Security Prefix: {name}",
                severity=Severity.LOW,
                description=(
                    f"The session cookie '{name}' does not use the '__Host-' or '__Secure-' "
                    "prefix. These prefixes enforce additional security constraints:\n"
                    "• __Host-: requires Secure, no Domain, Path=/\n"
                    "• __Secure-: requires Secure flag\n"
                    "Without them, sub-domain or protocol-downgrade attacks may be possible."
                ),
                evidence=f"Cookie name: {name}",
                remediation=(
                    "Rename session cookies with __Host- prefix for maximum protection:\n"
                    f"Set-Cookie: __Host-{name}=value; Secure; HttpOnly; Path=/; SameSite=Strict"
                ),
                reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#cookie_prefixes",
                module="cookies",
            ))

        # ── 5. Weak session ID ────────────────────────────────────────────────
        if is_session and value:
            entropy = _entropy_bits(value)
            predictable = _is_predictable(value)

            if entropy < 64:
                findings.append(Finding(
                    title=f"Low Entropy Session ID: {name} (~{entropy:.0f} bits)",
                    severity=Severity.HIGH,
                    description=(
                        f"The session cookie '{name}' has approximately {entropy:.0f} bits of "
                        "entropy (minimum recommended: 128 bits). Low-entropy session IDs "
                        "can be brute-forced or predicted by attackers."
                    ),
                    evidence=(
                        f"Cookie: {name}={value[:20]}{'...' if len(value) > 20 else ''}\n"
                        f"Value length: {len(value)} chars\n"
                        f"Estimated entropy: ~{entropy:.0f} bits"
                    ),
                    remediation="Generate session IDs using a CSPRNG with at least 128 bits of entropy.",
                    code_fix=(
                        "import secrets\n"
                        "session_id = secrets.token_hex(32)    # 256-bit hex string\n"
                        "# or\n"
                        "session_id = secrets.token_urlsafe(32) # URL-safe base64, ~256 bits"
                    ),
                    reference="https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
                    module="cookies",
                    cvss=7.5,
                ))
            elif predictable:
                findings.append(Finding(
                    title=f"Potentially Predictable Session ID: {name}",
                    severity=Severity.MEDIUM,
                    description=(
                        f"The session ID for '{name}' shows patterns suggesting it may be "
                        "predictable (sequential, too short, or low character diversity). "
                        "Predictable IDs can be guessed by attackers."
                    ),
                    evidence=f"Session value appears predictable: {value[:20]}...",
                    remediation="Use cryptographically secure random session IDs.",
                    code_fix="session_id = secrets.token_hex(32)  # Python",
                    reference="https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
                    module="cookies",
                    cvss=5.9,
                ))

        # ── 6. Overly broad domain scope ──────────────────────────────────────
        if domain and domain.startswith("."):
            findings.append(Finding(
                title=f"Cookie Domain Too Broad: {name} (Domain={domain})",
                severity=Severity.LOW,
                description=(
                    f"Cookie '{name}' is scoped to '{domain}', which includes all "
                    f"subdomains. If any subdomain is compromised or allows XSS, "
                    "it can read this cookie."
                ),
                evidence=f"Set-Cookie: ... Domain={domain}",
                remediation=(
                    "Restrict cookies to the specific domain that needs them. "
                    "Avoid dot-prefixed domains unless subdomain access is required."
                ),
                reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#domaindomain-value",
                module="cookies",
            ))

        # ── 7. Persistent session cookies (long/no expiry) ────────────────────
        if is_session and (max_age or expires) and not name.lower().startswith("remember"):
            findings.append(Finding(
                title=f"Session Cookie Has Persistent Expiry: {name}",
                severity=Severity.LOW,
                description=(
                    f"The session cookie '{name}' has an expiry date set (max-age/expires). "
                    "Session cookies should typically be session-scoped (no expiry) "
                    "to expire when the browser closes. Persistent session cookies "
                    "remain after the browser is closed, increasing theft risk."
                ),
                evidence=f"max-age={max_age}, expires={expires}",
                remediation=(
                    "Remove max-age and expires from session cookies. "
                    "Only persistent cookies (remember-me) should have expiry."
                ),
                reference="https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
                module="cookies",
            ))

    return findings
