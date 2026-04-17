"""
Open Redirect Detection Module
Tests for open redirect vulnerabilities in URL parameters.
Learned from: GSEC, yawast-ng, Wapiti (mod_redirect)
"""

from __future__ import annotations
import re
from urllib.parse import urlparse, urlencode, parse_qs, urljoin
from typing import List
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

REDIRECT_PARAMS = [
    "redirect", "redirect_to", "redirect_url", "return", "return_url",
    "returnUrl", "returnTo", "next", "url", "goto", "target", "destination",
    "dest", "redir", "ref", "callback", "continue", "forward", "location",
    "to", "out", "view", "from", "go",
]

MALICIOUS_URL = "https://evil.com"


def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    base = url.rstrip("/")

    with get_client(timeout=timeout) as client:
        for param in REDIRECT_PARAMS:
            test_url = f"{base}?{param}={MALICIOUS_URL}"
            try:
                # Don't follow redirects — check the redirect target directly
                resp = client.get(test_url, follow_redirects=False)

                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("location", "")
                    if "evil.com" in location:
                        findings.append(Finding(
                            title=f"Open Redirect via '{param}' Parameter",
                            severity=Severity.MEDIUM,
                            description=(
                                f"The parameter '{param}' accepts arbitrary URLs and "
                                "redirects users to them. Attackers use this to create "
                                "convincing phishing links like: "
                                f"{base}?{param}=https://phishing-site.com "
                                "that appear to be from your domain."
                            ),
                            evidence=(
                                f"Request: GET {test_url}\n"
                                f"Response: HTTP {resp.status_code}\n"
                                f"Location: {location}"
                            ),
                            remediation=(
                                "Validate redirect URLs against a whitelist of allowed domains. "
                                "Never redirect to user-supplied URLs without validation."
                            ),
                            code_fix=(
                                "# Python — safe redirect check:\n"
                                "from urllib.parse import urlparse\n\n"
                                "ALLOWED_HOSTS = ['yourdomain.com', 'app.yourdomain.com']\n\n"
                                "def safe_redirect(url):\n"
                                "    parsed = urlparse(url)\n"
                                "    if parsed.netloc and parsed.netloc not in ALLOWED_HOSTS:\n"
                                "        return '/'\n"  # default safe redirect
                                "    return url\n\n"
                                "# Django: use next parameter validation\n"
                                "# url_is_safe = url_has_allowed_host_and_scheme(url, allowed_hosts)"
                            ),
                            reference="https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
                            cvss=6.1,
                        ))
                        break  # one finding per site is enough

            except Exception:
                continue

    return findings
