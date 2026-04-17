"""
DOM-Based XSS & Client-Side Vulnerability Detection Module (v1.5.0)
OWASP A03:2025 - Injection | CVSS up to 8.8

DOM XSS is different from reflected XSS:
  - Reflected XSS: server reflects payload in HTML response
  - DOM XSS: JavaScript reads attacker-controlled data SOURCE and writes to dangerous SINK
  - The payload never goes to the server — it's processed entirely in the browser

  Common DOM XSS Sources (attacker-controlled input):
  • location.hash       (#fragment — not sent to server, ideal for DOM XSS)
  • location.search     (?query=...)
  • location.href       (full URL)
  • document.referrer   (Referer header)
  • document.cookie     (if readable)
  • postMessage data    (cross-frame messaging)
  • localStorage / sessionStorage

  Common DOM XSS Sinks (dangerous JavaScript functions):
  • innerHTML, outerHTML, insertAdjacentHTML  → XSS
  • document.write, document.writeln         → XSS
  • eval(), setTimeout(str), setInterval(str) → code execution
  • location.href = , location.assign()       → javascript: URL
  • src attribute assignment                 → script execution
  • jQuery $(), .html(), .append()           → XSS

  Detection approach (static analysis of page JavaScript):
  1. Fetch the page and all linked JS files
  2. Search for patterns where sources flow into sinks
  3. Look for dangerous jQuery patterns, eval, innerHTML with URL params
  4. Check for postMessage without origin validation

References:
  - PortSwigger: https://portswigger.net/web-security/cross-site-scripting/dom-based
  - DOM Invader (Burp Suite)
  - OWASP DOM-based XSS prevention cheat sheet
"""

from __future__ import annotations
import re
from typing import List, Tuple
from urllib.parse import urlparse
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client


# ─── Source patterns (attacker-controlled input) ──────────────────────────────
SOURCE_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"location\.(?:hash|search|href|pathname)", re.I), "location.*"),
    (re.compile(r"document\.(?:referrer|URL|documentURI)", re.I), "document.*"),
    (re.compile(r"window\.name", re.I), "window.name"),
    (re.compile(r"document\.cookie", re.I), "document.cookie"),
    (re.compile(r"localStorage\.getItem\(", re.I), "localStorage"),
    (re.compile(r"sessionStorage\.getItem\(", re.I), "sessionStorage"),
]

# ─── Sink patterns (dangerous write operations) ───────────────────────────────
SINK_PATTERNS: List[Tuple[re.Pattern, str, Severity]] = [
    # High severity sinks
    (re.compile(r"\.innerHTML\s*=", re.I),            "innerHTML assignment", Severity.HIGH),
    (re.compile(r"\.outerHTML\s*=", re.I),            "outerHTML assignment", Severity.HIGH),
    (re.compile(r"insertAdjacentHTML\s*\(", re.I),    "insertAdjacentHTML",   Severity.HIGH),
    (re.compile(r"document\.write\s*\(", re.I),       "document.write",       Severity.HIGH),
    (re.compile(r"document\.writeln\s*\(", re.I),     "document.writeln",     Severity.HIGH),
    # Critical sinks (code execution)
    (re.compile(r"\beval\s*\(", re.I),                "eval()",               Severity.CRITICAL),
    (re.compile(r"setTimeout\s*\(\s*[^,\)]+\+", re.I), "setTimeout(str+..)", Severity.HIGH),
    (re.compile(r"setInterval\s*\(\s*[^,\)]+\+", re.I), "setInterval(str+..)", Severity.HIGH),
    (re.compile(r"Function\s*\(", re.I),              "Function constructor", Severity.CRITICAL),
    (re.compile(r"new\s+Function\s*\(", re.I),        "new Function()",       Severity.CRITICAL),
    # URL-based sinks
    (re.compile(r"location\.href\s*=", re.I),         "location.href =",      Severity.MEDIUM),
    (re.compile(r"location\.replace\s*\(", re.I),     "location.replace()",   Severity.MEDIUM),
    (re.compile(r"location\.assign\s*\(", re.I),      "location.assign()",    Severity.MEDIUM),
    (re.compile(r'\.src\s*=\s*["\']?\s*(?:location|document)', re.I), "src=source", Severity.HIGH),
    # jQuery sinks
    (re.compile(r'\$\s*\(\s*(?:location|document\.URL)', re.I), "jQuery(source)", Severity.HIGH),
    (re.compile(r'\.html\s*\(\s*(?:location|document)', re.I),  "$.html(source)", Severity.HIGH),
    (re.compile(r'\.append\s*\(\s*(?:location|document)', re.I),"$.append(source)",Severity.HIGH),
]

# ─── Direct Source→Sink patterns (high confidence) ───────────────────────────
DIRECT_FLOW_PATTERNS: List[Tuple[re.Pattern, str, Severity]] = [
    # location.hash → innerHTML
    (re.compile(
        r"(?:location\.hash|location\.search|location\.href)[^\n;]{0,80}(?:innerHTML|outerHTML|insertAdjacentHTML|document\.write)",
        re.I | re.S
    ), "location.* → innerHTML/write", Severity.HIGH),

    # URL params → eval
    (re.compile(
        r"(?:location\.(?:hash|search|href))[^\n;]{0,100}eval\s*\(",
        re.I | re.S
    ), "location.* → eval()", Severity.CRITICAL),

    # document.referrer → sink
    (re.compile(
        r"document\.referrer[^\n;]{0,80}(?:innerHTML|document\.write|eval)",
        re.I | re.S
    ), "document.referrer → sink", Severity.HIGH),

    # postMessage without origin check
    (re.compile(
        r"addEventListener\s*\(\s*['\"]message['\"][^\)]*\)(?!.*origin)",
        re.I | re.S
    ), "postMessage without origin check", Severity.HIGH),

    # Prototype pollution via URL params
    (re.compile(
        r"(?:location\.search|URLSearchParams)[^\n;]{0,100}__proto__",
        re.I | re.S
    ), "prototype pollution via URL", Severity.HIGH),
]

# ─── Dangerous patterns by themselves ────────────────────────────────────────
STANDALONE_DANGEROUS: List[Tuple[re.Pattern, str, Severity]] = [
    # dangerouslySetInnerHTML in React — but ONLY if it's used with a variable (not the framework definition)
    (re.compile(r"dangerouslySetInnerHTML\s*=\s*\{\{?\.?__html\s*:\s*(?!['\"]).{0,50}\}", re.I),
     "React dangerouslySetInnerHTML with variable (not string literal)",
     Severity.MEDIUM),

    # v-html in Vue
    (re.compile(r"v-html\s*=", re.I),
     "Vue v-html directive (check if user data is used)",
     Severity.MEDIUM),

    # bypassSecurityTrustHtml in Angular
    (re.compile(r"bypassSecurityTrust(?:Html|Script|Style|Url|ResourceUrl)", re.I),
     "Angular bypassSecurityTrust* — security bypass",
     Severity.HIGH),

    # Hash-based routing reading (common DOM XSS entry point)
    (re.compile(r"decodeURIComponent\s*\(\s*location\.hash", re.I),
     "decodeURIComponent(location.hash) — classic DOM XSS source",
     Severity.MEDIUM),

    # jQuery selector from URL hash (classic vulnerability)
    (re.compile(r"\$\s*\(\s*(?:decodeURIComponent\s*\()?\s*(?:window\.)?location\.hash", re.I),
     "jQuery(location.hash) — classic DOM XSS",
     Severity.HIGH),
]

# ─── postMessage origin validation check ─────────────────────────────────────
POSTMESSAGE_NO_ORIGIN = re.compile(
    r"addEventListener\s*\(\s*['\"]message['\"].*?function\s*\([^)]*\)\s*\{(?!.*?event\.origin)",
    re.I | re.S
)


def _extract_js_urls(html: str, base_url: str) -> List[str]:
    """Extract JavaScript file URLs from HTML."""
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    js_urls = []

    for match in re.finditer(
        r'<script[^>]*\bsrc=["\']([^"\']+)["\']',
        html, re.I
    ):
        src = match.group(1)
        if src.startswith("http"):
            js_urls.append(src)
        elif src.startswith("//"):
            js_urls.append(f"{parsed.scheme}:{src}")
        elif src.startswith("/"):
            js_urls.append(f"{base}{src}")
        else:
            js_urls.append(f"{base_url.rstrip('/')}/{src}")

    return js_urls[:8]  # check first 8 JS files


def _analyze_js(js_content: str, source_url: str, findings: List[Finding]) -> None:
    """Analyze a JavaScript file/block for DOM XSS patterns."""
    seen_sinks = set()

    # 1. Direct source→sink flows (highest confidence)
    for (pattern, desc, severity) in DIRECT_FLOW_PATTERNS:
        m = pattern.search(js_content)
        if m:
            snippet = js_content[max(0, m.start()-40):m.end()+80].replace("\n", " ")
            findings.append(Finding(
                title=f"DOM XSS — Source→Sink Flow: {desc}",
                severity=severity,
                description=(
                    f"Detected a direct data flow from a browser-controlled source "
                    f"to a dangerous sink: {desc}. "
                    "This is a high-confidence DOM XSS indicator. "
                    "An attacker can craft a URL with a malicious payload in the "
                    "fragment (#) or query string that executes JavaScript in the victim's browser."
                ),
                evidence=(
                    f"Source: {source_url}\n"
                    f"Pattern: {desc}\n"
                    f"Code snippet: ...{snippet}..."
                ),
                remediation=(
                    "Never pass URL-derived data directly to HTML sinks. "
                    "Sanitize with DOMPurify before any innerHTML assignment. "
                    "Use textContent instead of innerHTML when displaying user data."
                ),
                code_fix=(
                    "// ❌ VULNERABLE:\n"
                    "document.getElementById('out').innerHTML = location.hash.slice(1);\n\n"
                    "// ✅ SAFE — use textContent:\n"
                    "document.getElementById('out').textContent = location.hash.slice(1);\n\n"
                    "// ✅ Or sanitize with DOMPurify if HTML is needed:\n"
                    "import DOMPurify from 'dompurify';\n"
                    "element.innerHTML = DOMPurify.sanitize(userInput);\n\n"
                    "// ✅ React — use state, not dangerouslySetInnerHTML:\n"
                    "<p>{userInput}</p>  {/* auto-escaped */}"
                ),
                reference="https://portswigger.net/web-security/cross-site-scripting/dom-based",
                cvss=8.8 if severity == Severity.CRITICAL else 6.1,
            ))
            return  # one finding per file

    # 2. Standalone dangerous patterns
    for (pattern, desc, severity) in STANDALONE_DANGEROUS:
        if pattern.search(js_content) and desc not in seen_sinks:
            seen_sinks.add(desc)
            m = pattern.search(js_content)
            snippet = js_content[max(0, m.start()-20):m.end()+60].replace("\n", " ")
            findings.append(Finding(
                title=f"DOM XSS Risk — {desc}",
                severity=severity,
                description=(
                    f"Potentially dangerous DOM operation detected: {desc}. "
                    "Manual review recommended to confirm if user-controlled input "
                    "reaches this sink."
                ),
                evidence=(
                    f"Source: {source_url}\n"
                    f"Code snippet: ...{snippet}..."
                ),
                remediation=(
                    "Review all data flowing into this operation. "
                    "Sanitize with DOMPurify if HTML rendering is required. "
                    "Use framework's built-in escaping where possible."
                ),
                reference="https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html",
                cvss=6.1,
            ))


def scan(url: str, timeout: float = 12.0) -> List[Finding]:
    findings: List[Finding] = []
    from urllib.parse import urlparse as _up
    parsed = _up(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    with get_client(timeout=min(timeout, 10.0)) as client:
        # Collect HTML from base URL + common JS-heavy pages
        html_sources = []
        for path in ["", "/dom", "/app", "/", "/dashboard", "/home"]:
            try:
                r = client.get(base + path)
                if r.status_code == 200 and "html" in r.headers.get("content-type", ""):
                    html_sources.append((base + path, r.text))
                    if len(html_sources) >= 3:
                        break
            except Exception:
                continue
        if not html_sources:
            return []
        _, html = html_sources[0]
        resp_url = base
        try:
            resp = client.get(url)
            html = resp.text
        except Exception:
            pass

        # 1. Analyze inline scripts in HTML across all sources
        all_html = "\n".join(h for _, h in html_sources) if html_sources else html
        inline_scripts = re.findall(
            r"<script(?!\s+src)[^>]*>(.*?)</script>",
            all_html, re.I | re.S
        )
        combined_inline = "\n".join(inline_scripts)
        if combined_inline.strip():
            _analyze_js(combined_inline, f"{url} [inline]", findings)

        if findings:
            return findings[:3]  # cap at 3

        # 2. Analyze external JS files — skip known CDN/framework libraries
        SKIP_PATTERNS = [
            "jquery.min", "jquery-", "react.min", "react.development",
            "react-dom.min", "react-dom.development", "vue.min", "vue.js",
            "angular.min", "bootstrap.min", "lodash.min", "moment.min",
            "/cdn-cgi/", "cloudflare", "googleapis.com", "jsdelivr.net",
            "unpkg.com", "cdnjs.cloudflare.com",
        ]
        js_urls = _extract_js_urls(html, url)
        for js_url in js_urls:
            # Skip CDN/framework files — focus on app-specific JS
            if any(skip in js_url.lower() for skip in SKIP_PATTERNS):
                continue
            try:
                js_resp = client.get(js_url)
                if js_resp.status_code == 200 and js_resp.text:
                    _analyze_js(js_resp.text, js_url, findings)
                    if len(findings) >= 2:
                        break
            except Exception:
                continue

    return findings
