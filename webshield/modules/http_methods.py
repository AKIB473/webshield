"""
HTTP Methods Module
Checks for dangerous HTTP methods: PUT, DELETE, TRACE, CONNECT, PATCH.
Learned from: Wapiti (mod_methods), GSEC (optionscheck), w4af
"""

from __future__ import annotations
from typing import List
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

DANGEROUS_METHODS = {
    "PUT":     (Severity.CRITICAL, "Allows uploading arbitrary files to the server. Attackers can upload web shells."),
    "DELETE":  (Severity.CRITICAL, "Allows deleting files from the server."),
    "TRACE":   (Severity.MEDIUM,   "TRACE can be used in Cross-Site Tracing (XST) attacks to steal cookies even with HttpOnly."),
    "CONNECT": (Severity.MEDIUM,   "CONNECT method can be abused to proxy traffic through your server."),
}


def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []

    with get_client(timeout=timeout) as client:
        # First, check OPTIONS to see what the server advertises
        try:
            resp = client.request("OPTIONS", url)
            allow_header = resp.headers.get("allow", "") + " " + resp.headers.get("public", "")
            allow_upper = allow_header.upper()

            for method, (severity, description) in DANGEROUS_METHODS.items():
                if method in allow_upper:
                    findings.append(Finding(
                        title=f"Dangerous HTTP Method Allowed: {method}",
                        severity=severity,
                        description=description,
                        evidence=f"OPTIONS response Allow: {allow_header.strip()}",
                        remediation=f"Disable the {method} method unless explicitly required.",
                        code_fix=(
                            f"# Nginx — restrict to GET/POST only:\n"
                            f"if ($request_method !~ ^(GET|POST|HEAD)$) {{\n"
                            f"    return 405;\n}}\n\n"
                            f"# Apache:\n"
                            f"<LimitExcept GET POST HEAD>\n"
                            f"    Require all denied\n"
                            f"</LimitExcept>"
                        ),
                        reference="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods",
                        cvss=9.1 if severity == Severity.CRITICAL else 5.3,
                    ))
        except Exception:
            pass

        # Actively probe TRACE (XST)
        try:
            resp = client.request("TRACE", url)
            if resp.status_code in (200, 201, 204):
                body_lower = resp.text.lower()
                # Real TRACE echoes back the request
                if "trace" in body_lower or "max-forwards" in body_lower:
                    findings.append(Finding(
                        title="HTTP TRACE Method Enabled (XST Risk)",
                        severity=Severity.MEDIUM,
                        description=(
                            "The server accepts TRACE requests and echoes back the request. "
                            "This enables Cross-Site Tracing (XST) which can be used to "
                            "steal HttpOnly cookies via JavaScript in older browsers."
                        ),
                        evidence=f"TRACE {url} → HTTP {resp.status_code}",
                        remediation="Disable the TRACE method on your web server.",
                        code_fix=(
                            "# Nginx:\n"
                            "if ($request_method = TRACE) { return 405; }\n\n"
                            "# Apache:\n"
                            "TraceEnable off"
                        ),
                        reference="https://owasp.org/www-community/attacks/Cross_Site_Tracing",
                        cvss=5.3,
                    ))
        except Exception:
            pass

    return findings
