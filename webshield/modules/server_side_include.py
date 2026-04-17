"""Server-Side Include (SSI) Injection Module (v1.8.0)"""
from __future__ import annotations
import re
from typing import List
from urllib.parse import urlparse, parse_qs
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

SSI_EXEC_RESULT = re.compile(r"uid=\d+|root:.*:/bin/|Windows IP|inet addr", re.I)
SSI_INCLUDE_RESULT = re.compile(r"root:[x*]?:0:0|/etc/passwd|\\[boot loader\\]", re.I)
SSI_DATE_RESULT = re.compile(r"\w{3},?\s+\d{1,2}\s+\w{3}\s+\d{4}|\d{4}-\d{2}-\d{2}")

SSI_PAYLOADS = [
    ('<!--#exec cmd="id"-->',              SSI_EXEC_RESULT,    "SSI exec RCE (id command)"),
    ('<!--#exec cmd="ipconfig"-->',        SSI_EXEC_RESULT,    "SSI exec RCE (ipconfig)"),
    ('<!--#include virtual="/etc/passwd"-->',SSI_INCLUDE_RESULT,"SSI file include (/etc/passwd)"),
    ('<!--#echo var="DATE_LOCAL"-->',      SSI_DATE_RESULT,    "SSI echo (date) — confirms SSI parsing"),
    ('<!--#printenv-->',                   re.compile(r"HTTP_HOST|DOCUMENT_ROOT|SERVER_",re.I),"SSI printenv"),
]

def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    parsed   = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    params   = parse_qs(parsed.query)

    with get_client(timeout=min(timeout, 8.0)) as client:
        test_params = list(params.keys()) or ["name","q","input","search","id","page"]
        for param in test_params[:3]:
            for (payload, pattern, desc) in SSI_PAYLOADS:
                try:
                    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    r = client.get(f"{base}?{param}={payload}")
                    if pattern.search(r.text):
                        findings.append(Finding(
                            title=f"Server-Side Include (SSI) Injection — {param}",
                            severity=Severity.CRITICAL,
                            description=(
                                f"SSI injection confirmed: {desc}. "
                                "The web server is executing SSI directives from user input. "
                                "This allows Remote Code Execution, file reads, and full server compromise."
                            ),
                            evidence=f"Payload: {payload}\nResponse: {r.text[:200]}",
                            remediation=(
                                "Disable SSI processing or restrict it to trusted files. "
                                "Never reflect user input in SSI-enabled pages without escaping."
                            ),
                            code_fix=(
                                "# Apache — disable SSI:\n"
                                "Options -Includes\n\n"
                                "# Or escape SSI delimiters in user input:\n"
                                "safe = input.replace('<!--', '&lt;!--').replace('-->', '--&gt;')"
                            ),
                            reference="https://owasp.org/www-community/attacks/Server-Side_Includes_(SSI)_Injection",
                            module="server_side_include",
                            cvss=9.8,
                        ))
                        return findings
                except Exception:
                    continue
    return findings
