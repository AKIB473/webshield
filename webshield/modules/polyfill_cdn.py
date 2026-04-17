"""Polyfill.io & Malicious CDN Detection Module (v1.8.0) — ZAP rule 10115"""
from __future__ import annotations
import re
from typing import List
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

MALICIOUS_CDNS = [
    (re.compile(r"polyfill\.io", re.I),       "polyfill.io",      "HIGH",  8.1,
     "The polyfill.io domain was compromised in 2024 and used to serve malicious JavaScript to millions of sites."),
    (re.compile(r"bootcss\.com", re.I),        "bootcss.com",      "HIGH",  7.5,
     "bootcss.com has been flagged as a malicious CDN distributing modified Bootstrap with injected code."),
    (re.compile(r"bootcdn\.net(?!\.cn)", re.I),"bootcdn.net",      "MEDIUM",5.3,
     "Unverified CDN — verify integrity attributes are present."),
    (re.compile(r"staticfile\.org", re.I),     "staticfile.org",   "HIGH",  7.5,
     "staticfile.org has been associated with supply chain attacks on Chinese CDN infrastructure."),
    (re.compile(r"cdn\.polyfill\.io", re.I),   "cdn.polyfill.io",  "HIGH",  8.1,
     "cdn.polyfill.io is a compromised CDN endpoint known to serve malicious scripts."),
]

SCRIPT_SRC = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
LINK_HREF  = re.compile(r'<link[^>]+href=["\']([^"\']+)["\']', re.I)
HAS_INTEGRITY = re.compile(r'\bintegrity=["\']sha', re.I)

def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []

    with get_client(timeout=min(timeout, 8.0)) as client:
        try:
            resp = client.get(url)
            if resp.status_code != 200:
                return findings
            body = resp.text

            # Check for malicious CDNs
            for (pattern, domain, sev, cvss, desc) in MALICIOUS_CDNS:
                scripts = SCRIPT_SRC.findall(body) + LINK_HREF.findall(body)
                matches = [s for s in scripts if pattern.search(s)]
                if matches:
                    # Check if they have integrity attributes
                    for match in matches[:3]:
                        # Find the full tag
                        tag_pattern = re.compile(
                            r'<(?:script|link)[^>]+' + re.escape(match) + r'[^>]*>',
                            re.I
                        )
                        tag = tag_pattern.search(body)
                        has_sri = tag and HAS_INTEGRITY.search(tag.group(0))

                        if not has_sri:
                            findings.append(Finding(
                                title=f"Malicious/Compromised CDN Detected: {domain}",
                                severity=Severity(sev),
                                description=(
                                    f"The page loads resources from {domain}. {desc}\n"
                                    "Scripts without Subresource Integrity (SRI) from compromised "
                                    "CDNs can execute arbitrary code in every visitor's browser."
                                ),
                                evidence=f"Resource URL: {match}\nNo integrity= attribute found",
                                remediation=(
                                    f"1. Remove all references to {domain} immediately.\n"
                                    "2. Replace with a trusted CDN (jsDelivr, cdnjs) with SRI hashes.\n"
                                    "3. Better: self-host critical JavaScript."
                                ),
                                code_fix=(
                                    "<!-- ❌ Vulnerable: -->\n"
                                    f'<script src="https://{domain}/polyfill.min.js"></script>\n\n'
                                    "<!-- ✅ Safe: self-hosted with SRI -->\n"
                                    '<script src="/js/polyfill.min.js"\n'
                                    '        integrity="sha384-HASH_HERE"\n'
                                    '        crossorigin="anonymous"></script>'
                                ),
                                reference="https://sansec.io/research/polyfill-supply-chain-attack",
                                module="polyfill_cdn",
                                cvss=cvss,
                            ))
                            break

            # Check for scripts from ANY third-party domain without SRI
            third_party_no_sri = []
            from urllib.parse import urlparse as _up
            page_host = _up(url).netloc
            for src in SCRIPT_SRC.findall(body):
                if not src.startswith(("/", "#")):
                    src_host = _up(src).netloc if src.startswith("http") else ""
                    if src_host and src_host != page_host:
                        tag_p = re.compile(r'<script[^>]+' + re.escape(src[:40]) + r'[^>]*>', re.I)
                        tag_m = tag_p.search(body)
                        if tag_m and not HAS_INTEGRITY.search(tag_m.group(0)):
                            third_party_no_sri.append(src)

            if len(third_party_no_sri) >= 3:
                findings.append(Finding(
                    title=f"Multiple Third-Party Scripts Without SRI ({len(third_party_no_sri)} found)",
                    severity=Severity.MEDIUM,
                    description=(
                        f"{len(third_party_no_sri)} third-party scripts are loaded without "
                        "Subresource Integrity (SRI) hashes. If any CDN is compromised, "
                        "malicious code will execute on your users' browsers."
                    ),
                    evidence=f"Scripts without SRI: {third_party_no_sri[:3]}",
                    remediation="Add integrity= and crossorigin= attributes to all third-party scripts.",
                    code_fix=(
                        "# Generate SRI hash:\ncurl https://cdn.example.com/lib.js | openssl dgst -sha384 -binary | openssl base64 -A\n\n"
                        '<script src="https://cdn.example.com/lib.js"\n'
                        '        integrity="sha384-GENERATED_HASH"\n'
                        '        crossorigin="anonymous"></script>'
                    ),
                    reference="https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity",
                    module="polyfill_cdn",
                    cvss=5.3,
                ))
        except Exception:
            pass
    return findings
