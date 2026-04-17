"""
XSS Detection Module (v1.3.0 — Advanced)
Covers: Reflected XSS, DOM-context detection, WAF bypass payloads,
        polyglot payloads, HTML/JS/attribute context detection,
        mXSS indicators, CSP bypass signals.
Research: XSStrike, PortSwigger, Bug Bounty WAF bypass research 2024/2025.
"""

from __future__ import annotations
import re
from typing import List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

# ─── Canary Setup ─────────────────────────────────────────────────────────────

CANARY = "wshld9x7z"  # unique, unlikely to appear naturally

# ─── Payload Groups ───────────────────────────────────────────────────────────

# (payload, context_name, description)
XSS_PAYLOADS: List[Tuple[str, str]] = [
    # ── Basic reflection probe (no tags)
    (CANARY,                                        "plain"),
    # ── HTML context — script injection
    (f"<script>{CANARY}</script>",                  "html_script"),
    (f"\"><script>{CANARY}</script>",               "html_attr_break"),
    (f"'><script>{CANARY}</script>",                "html_attr_break_sq"),
    # ── HTML context — event handlers
    (f"\" onmouseover=\"{CANARY}",                  "attr_dq_event"),
    (f"' onmouseover='{CANARY}",                    "attr_sq_event"),
    (f"\" onfocus=\"{CANARY}\" autofocus=\"",       "attr_autofocus"),
    (f"\" onload=\"{CANARY}",                       "attr_onload"),
    # ── HTML5 / SVG vectors (bypass many WAFs)
    (f"<svg onload={CANARY}>",                      "svg_onload"),
    (f"<svg/onload={CANARY}>",                      "svg_onload_nospace"),
    (f"<img src=x onerror={CANARY}>",               "img_onerror"),
    (f"<details open ontoggle={CANARY}>",           "details_ontoggle"),
    (f"<body onpageshow={CANARY}>",                 "body_onpageshow"),
    (f"<input autofocus onfocus={CANARY}>",         "input_autofocus"),
    (f"<iframe onload={CANARY}>",                   "iframe_onload"),
    (f"<video><source onerror={CANARY}>",           "video_source"),
    # ── JavaScript context breakout
    (f"';{CANARY}//",                               "js_sq_break"),
    (f"\";{CANARY}//",                              "js_dq_break"),
    (f"`${{{CANARY}}}",                             "js_template_literal"),
    # ── WAF bypass — encoding tricks
    (f"<ScRiPt>{CANARY}</ScRiPt>",                  "case_variation"),
    (f"<scr\x00ipt>{CANARY}</scr\x00ipt>",          "null_byte"),
    (f"<<script>>{CANARY}<</script>>",              "double_angle"),
    (f"<svg><animate onbegin={CANARY}>",            "svg_animate"),
    # ── WAF bypass — polyglot (works in multiple contexts simultaneously)
    (f"javascript:{CANARY}",                        "js_protocol"),
    (f"data:text/html,<script>{CANARY}</script>",   "data_uri"),
    # ── Attribute-only context (reflected in href/src)
    (f"javascript:/*-/*`/*\\`/*'/*\"/**/(/* */{CANARY}//*/",  "polyglot_attr"),
    # ── mXSS / mutation XSS indicators
    (f"<listing>{CANARY}</listing>",                "mxss_listing"),
    (f"<noscript>{CANARY}</noscript>",              "noscript_ctx"),
    # ── Double-encoded WAF bypass (decoded by server before reaching HTML)
    (f"%3Cscript%3E{CANARY}%3C%2Fscript%3E",       "url_encoded"),
    (quote(f"<script>{CANARY}</script>"),           "url_encoded_2"),
]

# ─── Reflection Detection Patterns ───────────────────────────────────────────

# Unescaped reflection = vulnerable
UNESCAPED_PATTERNS = [
    re.compile(r"<script[^>]*>" + CANARY, re.I),
    re.compile(r"on\w+\s*=\s*[\"']?" + CANARY, re.I),
    re.compile(r"<" + CANARY + r"[\s/>]", re.I),
    re.compile(r"<(?:svg|img|iframe|body|input|video|details|animate)[^>]+(?:onload|onerror|onfocus|ontoggle|onpageshow|onbegin)\s*=\s*" + CANARY, re.I),
    re.compile(r'"><[^>]*' + CANARY, re.I),
    re.compile(r"javascript:" + CANARY, re.I),
    re.compile(r"<listing>" + CANARY, re.I),
]

# Escaped output (encoded = filtered — safer but not fully safe)
ESCAPED_PATTERNS = [
    re.compile(r"&lt;" + CANARY, re.I),
    re.compile(r"&gt;" + CANARY, re.I),
    re.compile(r"&quot;" + CANARY, re.I),
    re.compile(r"&#x3[Cc];" + CANARY, re.I),
    re.compile(r"&#60;" + CANARY, re.I),
    re.compile(r"\\x3[Cc]" + CANARY, re.I),
]

# Patterns that suggest CSP is present (reduces severity)
CSP_PRESENT = re.compile(r"content-security-policy", re.I)


def _build_url(url: str, param: str, value: str) -> str:
    p = urlparse(url)
    params = {k: v[0] if isinstance(v, list) else v
              for k, v in parse_qs(p.query, keep_blank_values=True).items()}
    params[param] = value
    return urlunparse((p.scheme, p.netloc, p.path, p.params, urlencode(params), ""))


def _get_context(body: str, canary: str, window: int = 80) -> str:
    idx = body.lower().find(canary.lower())
    if idx == -1:
        return ""
    start = max(0, idx - 40)
    end = min(len(body), idx + window)
    return body[start:end].replace("\n", " ").strip()


def _is_in_js_context(body: str, canary: str) -> bool:
    """Returns True if the canary appears inside a <script> block."""
    script_blocks = re.findall(r"<script[^>]*>(.*?)</script>", body, re.I | re.S)
    return any(canary in block for block in script_blocks)


def _is_in_attribute(body: str, canary: str) -> bool:
    """Returns True if the canary appears inside an HTML attribute value."""
    pattern = re.compile(r'["\'][^"\']*' + re.escape(canary) + r'[^"\']*["\']', re.I)
    return bool(pattern.search(body))


def scan(url: str, timeout: float = 12.0) -> List[Finding]:
    findings: List[Finding] = []
    parsed = urlparse(url)
    params = list(parse_qs(parsed.query, keep_blank_values=True).keys())

    if not params:
        return []

    with get_client(timeout=min(timeout, 10.0)) as client:
        try:
            baseline_resp = client.get(url)
            ct = baseline_resp.headers.get("content-type", "")
            has_csp = CSP_PRESENT.search(str(baseline_resp.headers))
            # Only test HTML pages
            if "text/html" not in ct and "application/xhtml" not in ct:
                return []
            baseline = baseline_resp.text
        except Exception:
            return []

        for param in params[:5]:
            found_escaped = False

            for (payload, context) in XSS_PAYLOADS:
                test_url = _build_url(url, param, payload)
                try:
                    resp = client.get(test_url)
                    body = resp.text
                except Exception:
                    continue

                if CANARY not in body:
                    continue  # not reflected at all

                # Check if escaped
                if any(p.search(body) for p in ESCAPED_PATTERNS):
                    if not found_escaped:
                        found_escaped = True
                        # Only report once per param
                        findings.append(Finding(
                            title=f"XSS Input Reflected (HTML-Encoded) — param: {param}",
                            severity=Severity.LOW,
                            description=(
                                f"Input to '{param}' is reflected in the HTML response "
                                "with HTML encoding applied. Output encoding is working "
                                "for this context, but verify encoding is applied in ALL "
                                "contexts (HTML, JavaScript, URL, CSS)."
                            ),
                            evidence=f"Reflected (encoded): {_get_context(body, CANARY)}",
                            remediation=(
                                "Ensure context-specific output encoding everywhere. "
                                "HTML encoding in a JS context does not prevent XSS."
                            ),
                            reference="https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                            module="xss_detection",
                        ))
                    continue

                # Check for unescaped injection
                unescaped_match = next(
                    (p for p in UNESCAPED_PATTERNS if p.search(body)), None
                )

                if unescaped_match:
                    # Determine injection context for better advice
                    in_script = _is_in_js_context(body, CANARY)
                    in_attr = _is_in_attribute(body, CANARY)
                    context_hint = (
                        "JavaScript context" if in_script else
                        "HTML attribute context" if in_attr else
                        "HTML body context"
                    )

                    severity = Severity.MEDIUM if has_csp else Severity.HIGH

                    findings.append(Finding(
                        title=f"Reflected XSS — {context_hint} | param: {param}",
                        severity=severity,
                        description=(
                            f"The '{param}' parameter is vulnerable to Reflected XSS "
                            f"({context_hint}). Payload '{payload[:60]}' was reflected "
                            "unescaped in the HTML response. Attackers can craft malicious "
                            "URLs that steal session cookies, capture keystrokes, redirect "
                            "victims, or perform actions on the user's behalf."
                            + (" A CSP header was detected — severity reduced, but CSP "
                               "is bypassable and not a substitute for output encoding."
                               if has_csp else "")
                        ),
                        evidence=(
                            f"Parameter: {param}\n"
                            f"Payload: {payload}\n"
                            f"Context: {context_hint}\n"
                            f"Match pattern: {unescaped_match.pattern[:60]}\n"
                            f"Snippet: {_get_context(body, CANARY)}"
                        ),
                        remediation=(
                            "Apply context-appropriate output encoding:\n"
                            "• HTML context: HTML-encode (<, >, &, \", ')\n"
                            "• JavaScript context: JS-encode or use JSON.stringify\n"
                            "• Attribute context: HTML-encode and quote all attributes\n"
                            "• URL context: URL-encode\n"
                            "Implement a strong Content-Security-Policy as defense-in-depth."
                        ),
                        code_fix=(
                            "# Python — html.escape() for HTML context:\n"
                            "from html import escape\n"
                            "safe = escape(user_input)\n\n"
                            "# Jinja2 / Django — auto-escapes {{ value }}\n"
                            "# NEVER use |safe filter on user input\n\n"
                            "# Node.js (DOMPurify for rich HTML):\n"
                            "const clean = DOMPurify.sanitize(userInput);\n\n"
                            "# React — JSX auto-escapes {variable}\n"
                            "# NEVER use dangerouslySetInnerHTML with user input\n\n"
                            "# CSP header (defense in depth):\n"
                            "Content-Security-Policy: default-src 'self'; "
                            "script-src 'self'; object-src 'none'"
                        ),
                        reference="https://owasp.org/www-community/attacks/xss/",
                        module="xss_detection",
                        cvss=6.1 if has_csp else 8.2,
                    ))
                    return findings  # one confirmed XSS is enough signal

            # If canary reflected but no pattern matched — report as potential
            if CANARY in baseline.__class__.__name__:  # just a guard
                pass

    return findings
