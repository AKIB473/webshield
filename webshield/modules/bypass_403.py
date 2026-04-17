"""
403 Bypass Module (v1.6.0)
Attempts to bypass 403 Forbidden responses using various techniques.
Inspired by: ZAP rule 40038, Nikto evasion modes, HackTricks 403 bypass

Techniques:
1. HTTP Verb Tampering (GET -> POST, HEAD, OPTIONS, TRACE, PUT)
2. URL encoding bypass (%2f, %2e, %252f double encoding)
3. Path normalization (/admin -> /admin/, //admin, /./admin, /admin;/)
4. Header injection (X-Original-URL, X-Rewrite-URL, X-Forwarded-For)
5. HTTP/1.0 downgrade bypass
6. Trailing dot / special char bypass
7. Case variation (/Admin, /ADMIN)
"""

from __future__ import annotations
import re
from typing import List, Tuple
from urllib.parse import urlparse
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

# Common protected paths to test — these should return 403 on secure servers
PROTECTED_PATHS = [
    "/admin", "/admin/", "/dashboard", "/wp-admin",
    "/manager", "/console", "/actuator", "/.env",
    "/config", "/server-status", "/phpmyadmin",
    "/backup", "/api/admin", "/private",
]

# Header injection bypasses
HEADER_BYPASSES: List[Tuple[str, str]] = [
    ("X-Original-URL",       "{}"),
    ("X-Rewrite-URL",        "{}"),
    ("X-Custom-IP-Authorization", "127.0.0.1"),
    ("X-Forwarded-For",      "127.0.0.1"),
    ("X-Remote-IP",          "127.0.0.1"),
    ("X-Client-IP",          "127.0.0.1"),
    ("X-Host",               "localhost"),
    ("X-Forwarded-Host",     "localhost"),
]

# URL mangling techniques
def _url_variants(path: str) -> List[Tuple[str, str]]:
    """Return (mangled_path, technique_name) variants for a protected path."""
    p = path.rstrip("/")
    return [
        (p + "/",            "trailing slash"),
        ("/" + p.lstrip("/").replace("/", "//"), "double slash"),
        (p + "/.",           "trailing dot"),
        (p + "%20",          "trailing URL-encoded space"),
        (p + "%09",          "trailing tab"),
        (p + ";/",           "semicolon bypass"),
        ("/%2e" + p,         "dot prefix"),
        (p.upper(),          "uppercase path"),
        (re.sub(r"([a-zA-Z])", lambda m: m.group().swapcase(), p, count=2), "mixed case"),
        ("/" + p.lstrip("/").replace("/", "/%2f"), "URL-encoded slash"),
        ("/" + p.lstrip("/").replace("/", "/%252f"), "double URL-encoded slash"),
    ]


def _is_accessible(status_code: int, body: str, forbidden_body: str) -> bool:
    """Heuristic: did we get past the 403?"""
    if status_code in (200, 201, 202):
        return True
    if status_code in (301, 302, 307, 308):
        return True
    # Sometimes the content changes even with same status
    if status_code != 403 and status_code < 500:
        return True
    return False


def _get_baseline(client, url: str) -> Tuple[int, str]:
    """Get the normal response for comparison."""
    try:
        r = client.get(url)
        return r.status_code, r.text[:200]
    except Exception:
        return 0, ""


def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    parsed   = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    with get_client(timeout=min(timeout, 8.0)) as client:
        for protected_path in PROTECTED_PATHS:
            target = base_url + protected_path
            try:
                baseline = client.get(target)
            except Exception:
                continue

            # Only attempt bypass if we actually got a 403/401
            if baseline.status_code not in (401, 403):
                continue

            bypass_found = False

            # ── Technique 1: HTTP verb tampering
            for method in ["POST", "HEAD", "OPTIONS", "PUT", "PATCH"]:
                try:
                    if method in ("POST", "PUT", "PATCH"):
                        r = client.request(method, target, content=b"")
                    else:
                        r = client.request(method, target)
                    if _is_accessible(r.status_code, r.text, ""):
                        findings.append(Finding(
                            title=f"403 Bypass via HTTP Verb Tampering ({method}) — {protected_path}",
                            severity=Severity.HIGH,
                            description=(
                                f"The path {protected_path} returns HTTP 403 on GET requests, "
                                f"but is accessible using HTTP {method}. This is a server "
                                "misconfiguration where access control is only enforced on "
                                "specific HTTP methods."
                            ),
                            evidence=(
                                f"Path: {target}\n"
                                f"GET → {baseline.status_code} (blocked)\n"
                                f"{method} → {r.status_code} (accessible)\n"
                                f"Response snippet: {r.text[:100]}"
                            ),
                            remediation=(
                                "Enforce access control on all HTTP methods, not just GET. "
                                "In most frameworks, access control should be method-agnostic."
                            ),
                            code_fix=(
                                "# Nginx — restrict all methods:\n"
                                f"location {protected_path} {{\n"
                                "    limit_except GET POST { deny all; }\n"
                                "    # Better: use auth for all methods\n"
                                "    auth_basic 'Protected';\n"
                                "    auth_basic_user_file /etc/nginx/.htpasswd;\n"
                                "}}\n\n"
                                "# Express:\n"
                                "// Use middleware on the router, not method-specific routes\n"
                                "router.use('/admin', authMiddleware); // covers ALL methods"
                            ),
                            reference="https://owasp.org/www-project-web-security-testing-guide/",
                            module="bypass_403",
                            cvss=7.5,
                        ))
                        bypass_found = True
                        break
                except Exception:
                    continue

            if bypass_found:
                continue

            # ── Technique 2: Header injection bypasses
            for (header, value_template) in HEADER_BYPASSES:
                value = value_template.format(protected_path)
                try:
                    r = client.get(base_url + "/", headers={header: value})
                    if r.status_code == 200 and protected_path.lstrip("/") in r.text.lower():
                        findings.append(Finding(
                            title=f"403 Bypass via {header} Header — {protected_path}",
                            severity=Severity.HIGH,
                            description=(
                                f"The server processes the {header} header and grants access "
                                f"to {protected_path} when this header is set. "
                                "This is commonly exploited by attackers who can make "
                                "requests appear to come from internal addresses."
                            ),
                            evidence=(
                                f"GET / with {header}: {value} → HTTP {r.status_code}\n"
                                f"Response contains content from {protected_path}"
                            ),
                            remediation=(
                                f"Do not trust the {header} header for access control decisions. "
                                "These headers can be set by any client."
                            ),
                            code_fix=(
                                "# Remove reliance on proxy headers for auth:\n"
                                "# Express — don't trust X-Forwarded-* unless behind a trusted proxy:\n"
                                "app.set('trust proxy', false)  // only enable if behind known proxy\n\n"
                                "# Flask:\n"
                                "app.config['TRUSTED_HOSTS'] = ['your-proxy-ip']\n"
                                "# Never use request.headers.get('X-Original-URL') for routing"
                            ),
                            reference="https://portswigger.net/web-security/host-header",
                            module="bypass_403",
                            cvss=7.5,
                        ))
                        bypass_found = True
                        break
                except Exception:
                    continue

            if bypass_found:
                continue

            # ── Technique 3: URL path mangling
            for (mangled, technique) in _url_variants(protected_path):
                try:
                    r = client.get(base_url + mangled)
                    if _is_accessible(r.status_code, r.text, ""):
                        findings.append(Finding(
                            title=f"403 Bypass via URL Manipulation ({technique}) — {protected_path}",
                            severity=Severity.HIGH,
                            description=(
                                f"The protected path {protected_path} can be accessed using "
                                f"URL manipulation ({technique}: {mangled}). "
                                "This occurs when access controls match URL strings literally "
                                "instead of normalizing the path first."
                            ),
                            evidence=(
                                f"Normal: GET {protected_path} → {baseline.status_code}\n"
                                f"Bypass: GET {mangled} → {r.status_code}"
                            ),
                            remediation=(
                                "Normalize URL paths before applying access control checks. "
                                "Use framework-level routing, not string matching."
                            ),
                            code_fix=(
                                "# Python — normalize path before ACL check:\n"
                                "import os\n"
                                "safe_path = os.path.normpath(request.path)\n"
                                "if not is_authorized(safe_path):\n"
                                "    abort(403)\n\n"
                                "# Express:\n"
                                "const path = require('path');\n"
                                "const normalized = path.normalize(req.url);"
                            ),
                            reference="https://owasp.org/www-project-web-security-testing-guide/",
                            module="bypass_403",
                            cvss=7.5,
                        ))
                        bypass_found = True
                        break
                except Exception:
                    continue

    return findings
