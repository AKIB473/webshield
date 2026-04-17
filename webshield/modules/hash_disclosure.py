"""Hash Disclosure Module (v1.8.0) — ZAP rule 10097"""
from __future__ import annotations
import re
from typing import List
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

HASH_PATTERNS = [
    (re.compile(r'\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}'),          "BCrypt",      Severity.HIGH,   8.1),
    (re.compile(r'\$6\$[./A-Za-z0-9]{8,16}\$[./A-Za-z0-9]{86}'), "SHA-512 Crypt",Severity.HIGH,  7.5),
    (re.compile(r'\$1\$[./A-Za-z0-9]{8}\$[./A-Za-z0-9]{22}'),    "MD5 Crypt",   Severity.HIGH,   7.5),
    (re.compile(r'\b[0-9a-f]{32}\b'),                              "MD5",         Severity.MEDIUM, 5.3),
    (re.compile(r'\b[0-9a-f]{40}\b'),                              "SHA-1",       Severity.MEDIUM, 5.3),
    (re.compile(r'\b[0-9a-f]{64}\b'),                              "SHA-256",     Severity.MEDIUM, 4.3),
    (re.compile(r'\b[0-9a-f]{128}\b'),                             "SHA-512",     Severity.MEDIUM, 4.3),
    (re.compile(r'[A-Za-z0-9+/]{27}='),                            "Base64(MD5)", Severity.LOW,    3.1),
    (re.compile(r'\{SSHA\}[A-Za-z0-9+/=]{28,}'),                   "SSHA (LDAP)", Severity.HIGH,   7.5),
    (re.compile(r'[0-9A-F]{32}:[0-9A-F]{32}', re.I),              "NTLM",        Severity.HIGH,   8.1),
]

CONTEXT_KEYWORDS = re.compile(r'password|passwd|hash|secret|credential|token', re.I)

def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    with get_client(timeout=min(timeout, 8.0)) as client:
        try:
            resp = client.get(url)
            if resp.status_code != 200:
                return findings
            body = resp.text[:50000]
            for (pattern, hash_type, severity, cvss) in HASH_PATTERNS:
                matches = pattern.findall(body)
                if not matches:
                    continue
                # Reduce false positives: look for password-related context nearby
                for m in matches[:3]:
                    idx = body.find(m)
                    context = body[max(0,idx-100):idx+100]
                    if CONTEXT_KEYWORDS.search(context) or hash_type in ("BCrypt","NTLM","SSHA (LDAP)","SHA-512 Crypt","MD5 Crypt"):
                        findings.append(Finding(
                            title=f"Password Hash Disclosed in Response — {hash_type}",
                            severity=severity,
                            description=(
                                f"A {hash_type} password hash was found in the HTTP response. "
                                "Exposed password hashes allow offline brute-force and rainbow table attacks."
                            ),
                            evidence=f"URL: {url}\nHash type: {hash_type}\nHash: {m[:40]}{'...' if len(m)>40 else ''}",
                            remediation="Never expose password hashes in API responses. Use field-level serializer exclusions.",
                            code_fix=(
                                "# Django REST Framework — exclude password field:\n"
                                "class UserSerializer(serializers.ModelSerializer):\n"
                                "    class Meta:\n"
                                "        exclude = ['password']\n\n"
                                "# Express:\n"
                                "const { password, ...safeUser } = user.toObject();\n"
                                "res.json(safeUser);"
                            ),
                            reference="https://owasp.org/www-project-web-security-testing-guide/",
                            module="hash_disclosure",
                            cvss=cvss,
                        ))
                        break
                if findings:
                    break
        except Exception:
            pass
    return findings
