"""
security.txt Module
Checks for RFC 9116 security.txt — a best practice for responsible disclosure.
Also validates its contents.
"""

from __future__ import annotations
from typing import List
import re
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

LOCATIONS = ["/.well-known/security.txt", "/security.txt"]

REQUIRED_FIELDS = ["Contact:", "Expires:"]
RECOMMENDED_FIELDS = ["Encryption:", "Acknowledgments:", "Policy:", "Preferred-Languages:"]


def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    base = url.rstrip("/")
    found_content = None
    found_url = None

    with get_client(timeout=timeout) as client:
        for path in LOCATIONS:
            try:
                resp = client.get(base + path)
                if resp.status_code == 200 and len(resp.text.strip()) > 10:
                    found_content = resp.text
                    found_url = base + path
                    break
            except Exception:
                continue

    if not found_content:
        findings.append(Finding(
            title="security.txt Not Found",
            severity=Severity.INFO,
            description=(
                "No security.txt file found at /.well-known/security.txt or /security.txt. "
                "RFC 9116 recommends this file so security researchers know how to "
                "responsibly report vulnerabilities they find on your site."
            ),
            evidence=f"Checked: {base}/.well-known/security.txt and {base}/security.txt",
            remediation="Create a security.txt file at /.well-known/security.txt.",
            code_fix=(
                "# /.well-known/security.txt\n"
                "Contact: mailto:security@yourdomain.com\n"
                "Expires: 2027-01-01T00:00:00.000Z\n"
                "Preferred-Languages: en\n"
                "Policy: https://yourdomain.com/security-policy"
            ),
            reference="https://securitytxt.org/",
        ))
        return findings

    findings.append(Finding(
        title="security.txt Found",
        severity=Severity.INFO,
        description=f"security.txt is present at {found_url}.",
        evidence=f"URL: {found_url}\n{found_content[:200]}",
        reference="https://securitytxt.org/",
    ))

    # Validate required fields
    for field in REQUIRED_FIELDS:
        if field.lower() not in found_content.lower():
            findings.append(Finding(
                title=f"security.txt Missing Required Field: {field}",
                severity=Severity.LOW,
                description=(
                    f"RFC 9116 requires the '{field}' field in security.txt. "
                    "Without it, the file is technically invalid."
                ),
                evidence=f"Field '{field}' not found in {found_url}",
                remediation=f"Add the '{field}' field to your security.txt.",
                code_fix=f"{field} mailto:security@yourdomain.com",
                reference="https://www.rfc-editor.org/rfc/rfc9116",
            ))

    # Check if Expires is in the past
    expires_match = re.search(r"Expires:\s*(.+)", found_content, re.IGNORECASE)
    if expires_match:
        import datetime
        expires_str = expires_match.group(1).strip()
        try:
            # Try ISO 8601 parse
            expires_dt = datetime.datetime.fromisoformat(
                expires_str.replace("Z", "+00:00")
            )
            now = datetime.datetime.now(datetime.timezone.utc)
            if expires_dt < now:
                findings.append(Finding(
                    title="security.txt Has Expired",
                    severity=Severity.LOW,
                    description=(
                        f"The security.txt Expires field ({expires_str}) is in the past. "
                        "An expired security.txt is treated as if it doesn't exist."
                    ),
                    evidence=f"Expires: {expires_str}",
                    remediation="Update the Expires field to a future date.",
                    code_fix=f"Expires: {(now + datetime.timedelta(days=365)).strftime('%Y-%m-%dT%H:%M:%S.000Z')}",
                    reference="https://www.rfc-editor.org/rfc/rfc9116",
                ))
        except Exception:
            pass

    return findings
