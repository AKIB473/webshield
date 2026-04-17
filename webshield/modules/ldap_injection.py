"""LDAP Injection Module (v1.8.0)"""
from __future__ import annotations
import re
from typing import List
from urllib.parse import urlparse, parse_qs
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

LDAP_ERROR = re.compile(
    r"LDAPException|ldap_search|Invalid DN|javax\.naming|"
    r"LdapErr|LDAP.*error|bad search filter|NamingException|"
    r"ldap_connect|ActiveDirectory|distinguishedName",
    re.I
)
LDAP_PAYLOADS = [
    ("auth_bypass", "*)(uid=*))(|(uid=*", "LDAP auth bypass via wildcard injection"),
    ("wildcard",    "*",                  "LDAP wildcard — returns all entries"),
    ("null_byte",   "\x00",               "Null byte LDAP filter termination"),
    ("special",     ")(|(cn=*",           "LDAP filter escape"),
    ("tautology",   "admin)(&(password=*)","LDAP tautology bypass"),
]

PROBE_PATHS = ["/login","/search","/api/search","/api/users","/directory","/ldap","/auth"]

def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    parsed   = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    params   = parse_qs(parsed.query)

    with get_client(timeout=min(timeout, 8.0)) as client:
        test_targets = list(params.keys()) or ["username", "user", "q", "search", "name"]

        for path in ([parsed.path] if params else PROBE_PATHS[:5]):
            for param in test_targets[:3]:
                for (name, payload, desc) in LDAP_PAYLOADS:
                    try:
                        test_url = f"{base_url}{path}?{param}={payload}"
                        r = client.get(test_url)
                        if LDAP_ERROR.search(r.text):
                            findings.append(Finding(
                                title=f"LDAP Injection — {name} ({param})",
                                severity=Severity.HIGH,
                                description=(
                                    f"LDAP injection detected in parameter '{param}'. "
                                    f"Technique: {desc}. "
                                    "LDAP injection allows attackers to bypass authentication, "
                                    "enumerate directory entries, and access unauthorized data."
                                ),
                                evidence=f"URL: {test_url}\nLDAP error: {LDAP_ERROR.search(r.text).group(0)}",
                                remediation="Escape all LDAP special characters: ( ) * \\ NUL / before using in filters.",
                                code_fix=(
                                    "# Python — escape LDAP special chars:\n"
                                    "from ldap3.utils.conv import escape_filter_chars\n"
                                    "safe = escape_filter_chars(user_input)\n"
                                    "filt = f'(uid={safe})'\n\n"
                                    "# Java:\n"
                                    "String safe = LdapEncoder.filterEncode(userInput);"
                                ),
                                reference="https://owasp.org/www-community/attacks/LDAP_Injection",
                                module="ldap_injection",
                                cvss=8.8,
                            ))
                            return findings
                        # Also try POST for login forms
                        r2 = client.post(
                            base_url + path,
                            content=f"username={payload}&password=test".encode(),
                            headers={"Content-Type": "application/x-www-form-urlencoded"},
                        )
                        if LDAP_ERROR.search(r2.text):
                            findings.append(Finding(
                                title=f"LDAP Injection via POST — {name}",
                                severity=Severity.HIGH,
                                description=f"LDAP injection in POST body username field. {desc}",
                                evidence=f"POST {base_url+path}\nPayload: {payload}\nError: {LDAP_ERROR.search(r2.text).group(0)}",
                                remediation="Escape all LDAP special characters before using in directory queries.",
                                code_fix="safe = escape_filter_chars(user_input)",
                                reference="https://owasp.org/www-community/attacks/LDAP_Injection",
                                module="ldap_injection",
                                cvss=8.8,
                            ))
                            return findings
                    except Exception:
                        continue
    return findings
