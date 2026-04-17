"""
CRLF Injection Module
Injects carriage-return/line-feed sequences into URL params to test header injection.
Learned from: Wapiti (mod_crlf.py)
"""

from __future__ import annotations
from typing import List
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

CRLF_PAYLOADS = [
    "%0d%0aWebShield-Test: injected",
    "%0aWebShield-Test: injected",
    "%0d%0a%20WebShield-Test: injected",
    "%E5%98%8D%E5%98%8AWebShield-Test: injected",    # UTF-8 encoded CRLF
    "%E5%98%8A%E5%98%8DWebShield-Test: injected",
    "\r\nWebShield-Test: injected",
    "\nWebShield-Test: injected",
]


def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    base_path = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))

    # Test params and path segments
    test_targets = list(params.keys())[:3] if params else []

    with get_client(timeout=timeout) as client:
        for payload in CRLF_PAYLOADS[:4]:
            # Test in URL path as query value
            for param in test_targets:
                new_params = dict(params)
                new_params[param] = [payload]
                test_url = base_path + "?" + urlencode(
                    {k: v[0] if isinstance(v, list) else v for k, v in new_params.items()}
                )
                try:
                    resp = client.get(test_url, follow_redirects=False)
                    if "webshield-test" in str(resp.headers).lower():
                        findings.append(Finding(
                            title="CRLF Injection / HTTP Response Splitting",
                            severity=Severity.HIGH,
                            description=(
                                "The server reflects CRLF characters in HTTP response headers. "
                                "Attackers can inject arbitrary headers, set malicious cookies, "
                                "perform XSS via reflected headers, or cache poison responses."
                            ),
                            evidence=(
                                f"Payload injected into '{param}': {payload!r}\n"
                                f"Injected header 'webshield-test' found in response headers."
                            ),
                            remediation=(
                                "Sanitize all user input before including it in HTTP response headers. "
                                "Strip or encode \\r and \\n characters from any value used in headers."
                            ),
                            code_fix=(
                                "# Python — strip CRLF:\n"
                                "def safe_header(value):\n"
                                "    return value.replace('\\r', '').replace('\\n', '')\n\n"
                                "# Never build headers from raw user input:\n"
                                "# Bad:  response.headers['Location'] = user_input\n"
                                "# Good: response.headers['Location'] = safe_header(user_input)"
                            ),
                            reference="https://owasp.org/www-community/attacks/HTTP_Response_Splitting",
                            cvss=6.1,
                        ))
                        return findings
                except Exception:
                    continue

            # Also test bare path injection
            try:
                test_url = base_path + payload
                resp = client.get(test_url, follow_redirects=False)
                if "webshield-test" in str(resp.headers).lower():
                    findings.append(Finding(
                        title="CRLF Injection in URL Path",
                        severity=Severity.HIGH,
                        description="CRLF characters in URL path are reflected in response headers.",
                        evidence=f"Payload: {payload!r}\nInjected header found in response.",
                        remediation="Sanitize CRLF characters from all inputs used in headers.",
                        code_fix="value.replace('\\r', '').replace('\\n', '')",
                        reference="https://owasp.org/www-community/attacks/HTTP_Response_Splitting",
                        cvss=6.1,
                    ))
                    return findings
            except Exception:
                continue

    return findings
