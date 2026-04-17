"""ASP.NET ViewState Scanner Module (v1.8.0) — ZAP rule 10032"""
from __future__ import annotations
import re, base64
from typing import List
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

VIEWSTATE_PATTERN = re.compile(r'<input[^>]+name=["\']__VIEWSTATE["\'][^>]+value=["\']([^"\']+)["\']', re.I)
MAC_INDICATOR     = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}$')
EMAIL_IN_VS       = re.compile(r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z]{2,}', re.I)
IP_IN_VS          = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
ASPNET_VERSION    = re.compile(r'X-AspNet-Version|X-AspNetMvc-Version', re.I)

def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    with get_client(timeout=min(timeout, 8.0)) as client:
        try:
            resp = client.get(url)
            headers = dict(resp.headers)

            # Check ASP.NET version header disclosure
            for h in headers:
                if ASPNET_VERSION.search(h):
                    findings.append(Finding(
                        title=f"ASP.NET Version Disclosed ({h}: {headers[h]})",
                        severity=Severity.LOW,
                        description="The ASP.NET version is exposed via response header, aiding attackers in finding version-specific exploits.",
                        evidence=f"{h}: {headers[h]}",
                        remediation="Remove version headers in Web.config: <httpRuntime enableVersionHeader='false'/>",
                        code_fix="<!-- Web.config -->\n<system.web>\n  <httpRuntime enableVersionHeader=\"false\"/>\n</system.web>",
                        reference="https://owasp.org/www-project-web-security-testing-guide/",
                        module="viewstate_scanner",
                        cvss=3.1,
                    ))

            # Check ViewState
            vs_match = VIEWSTATE_PATTERN.search(resp.text)
            if not vs_match:
                return findings

            vs_value = vs_match.group(1)

            # Try to decode ViewState
            try:
                decoded = base64.b64decode(vs_value + "==")
                decoded_str = decoded.decode("utf-8", errors="replace")
            except Exception:
                decoded_str = ""

            # Check for MAC signature (last 20 bytes = HMAC-SHA1 = 28 base64 chars)
            # ViewState without MAC is vulnerable to tampering
            # Heuristic: if it decodes to mostly printable text, MAC is likely missing
            if len(vs_value) < 100 or (decoded_str and decoded_str.count('\x00') > len(decoded_str) * 0.3):
                findings.append(Finding(
                    title="ASP.NET ViewState Without MAC Signature",
                    severity=Severity.HIGH,
                    description=(
                        "The ViewState does not appear to have a Message Authentication Code (MAC). "
                        "Without MAC validation, attackers can tamper with the ViewState to manipulate "
                        "hidden form fields, bypass access controls, and potentially achieve deserialization RCE."
                    ),
                    evidence=f"ViewState value (first 80 chars): {vs_value[:80]}",
                    remediation="Enable ViewState MAC in Web.config: <pages enableViewStateMac='true' viewStateEncryptionMode='Always'/>",
                    code_fix=(
                        "<!-- Web.config -->\n<system.web>\n"
                        "  <pages enableViewStateMac=\"true\"\n"
                        "         viewStateEncryptionMode=\"Always\"\n"
                        "         enableEventValidation=\"true\"/>\n"
                        "</system.web>"
                    ),
                    reference="https://owasp.org/www-project-web-security-testing-guide/",
                    module="viewstate_scanner",
                    cvss=7.5,
                ))

            # Check for emails/IPs embedded in ViewState
            if decoded_str:
                emails = EMAIL_IN_VS.findall(decoded_str)
                ips    = IP_IN_VS.findall(decoded_str)
                if emails:
                    findings.append(Finding(
                        title="Email Addresses Found in ViewState",
                        severity=Severity.MEDIUM,
                        description=f"Email addresses found embedded in ViewState: {emails[:3]}. This may leak user PII.",
                        evidence=f"Emails in ViewState: {emails[:3]}",
                        remediation="Avoid storing sensitive data in ViewState. Use server-side session instead.",
                        code_fix="// Store sensitive data in Session, not ViewState:\nSession['userEmail'] = email;  // server-side only",
                        reference="https://owasp.org/www-project-web-security-testing-guide/",
                        module="viewstate_scanner",
                        cvss=4.3,
                    ))
                if ips:
                    findings.append(Finding(
                        title="IP Addresses Found in ViewState",
                        severity=Severity.MEDIUM,
                        description=f"Internal IP addresses in ViewState: {ips[:3]}. May reveal network topology.",
                        evidence=f"IPs in ViewState: {ips[:3]}",
                        remediation="Remove internal IP references from server-side data stored in ViewState.",
                        code_fix="// Don't store internal IPs or server addresses in ViewState",
                        reference="https://owasp.org/www-project-web-security-testing-guide/",
                        module="viewstate_scanner",
                        cvss=3.1,
                    ))
        except Exception:
            pass
    return findings
