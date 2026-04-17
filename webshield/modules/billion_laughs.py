"""Billion Laughs / Exponential Entity Expansion DoS Module (v1.8.0) — ZAP rule 40044"""
from __future__ import annotations
import re
import time
from typing import List
from urllib.parse import urlparse
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

# Classic billion laughs payload (truncated to avoid actual DoS)
BILLION_LAUGHS = """<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<root>&lol4;</root>"""

XML_ACCEPT = re.compile(r"xml|soap", re.I)
ERROR_SIGNS = re.compile(r"timeout|memory|entity.*expansion|billion|recursive|stack.*overflow|OutOfMemory", re.I)

PROBE_PATHS = ["/", "/api", "/api/xml", "/soap", "/ws", "/xmlrpc.php", "/api/v1"]

def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    parsed   = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    with get_client(timeout=min(timeout, 6.0)) as client:
        for path in PROBE_PATHS:
            for ct in ["application/xml", "text/xml"]:
                try:
                    t0 = time.time()
                    r = client.post(
                        base_url + path,
                        content=BILLION_LAUGHS.encode(),
                        headers={"Content-Type": ct},
                    )
                    elapsed = time.time() - t0

                    # Indicators: long response time (>3s), error messages, or memory-related errors
                    if elapsed > 3.0 or ERROR_SIGNS.search(r.text):
                        findings.append(Finding(
                            title=f"Billion Laughs XML DoS — {path}",
                            severity=Severity.MEDIUM,
                            description=(
                                f"The XML endpoint {path} appears vulnerable to Exponential Entity Expansion "
                                "(Billion Laughs attack). A malicious XML document with recursive entity "
                                "references can exhaust server memory and CPU, causing denial of service."
                            ),
                            evidence=(
                                f"URL: {base_url+path}\nContent-Type: {ct}\n"
                                f"Response time: {elapsed:.1f}s (>3s indicates DoS risk)\n"
                                f"HTTP {r.status_code}"
                            ),
                            remediation=(
                                "Disable DTD processing or limit entity expansion in your XML parser."
                            ),
                            code_fix=(
                                "# Python lxml — disable DTD:\n"
                                "from lxml import etree\n"
                                "parser = etree.XMLParser(load_dtd=False, no_network=True, resolve_entities=False)\n\n"
                                "# Java:\nfactory.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\n\n"
                                "# .NET:\nvar settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit };"
                            ),
                            reference="https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
                            module="billion_laughs",
                            cvss=7.5,
                        ))
                        return findings
                except Exception:
                    continue
    return findings
