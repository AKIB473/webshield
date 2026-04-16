"""
Subresource Integrity (SRI) Check Module (v1.0.1)
Checks external scripts/styles for missing integrity= attributes.
Learned from: yawast-ng (retirejs), XSStrike (retireJs plugin)
"""

from __future__ import annotations
import re
from typing import List, Tuple
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

# External CDN patterns — resources from these should have SRI
EXTERNAL_CDN_PATTERN = re.compile(
    r'<(script|link)[^>]+(?:src|href)=["\']'
    r'(https?://(?!(?:www\.)?(?:[^"\']+\.)?(?:localhost|127\.0\.0\.1))[^"\']+)["\']'
    r'[^>]*>',
    re.IGNORECASE,
)

HAS_INTEGRITY = re.compile(r'integrity=["\'][^"\']+["\']', re.IGNORECASE)

KNOWN_CDNS = [
    "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com",
    "code.jquery.com", "maxcdn.bootstrapcdn.com", "stackpath.bootstrapcdn.com",
    "fonts.googleapis.com", "ajax.googleapis.com", "ajax.aspnetcdn.com",
    "cdn.bootcss.com", "cdn.staticfile.org",
]


def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []

    try:
        with get_client(timeout=timeout) as client:
            resp = client.get(url)
    except Exception:
        return []

    body = resp.text
    missing_sri: List[Tuple[str, str]] = []

    for match in EXTERNAL_CDN_PATTERN.finditer(body):
        tag_full = match.group(0)
        tag_type = match.group(1).lower()  # script or link
        resource_url = match.group(2)

        # Only flag well-known CDNs (high confidence)
        is_known_cdn = any(cdn in resource_url for cdn in KNOWN_CDNS)
        if not is_known_cdn:
            continue

        if not HAS_INTEGRITY.search(tag_full):
            missing_sri.append((tag_type, resource_url))

    if missing_sri:
        examples = "\n".join(
            f"  <{t} src=\"{u[:80]}\">" for t, u in missing_sri[:5]
        )
        findings.append(Finding(
            title=f"Subresource Integrity (SRI) Missing on {len(missing_sri)} External Resource(s)",
            severity=Severity.MEDIUM,
            description=(
                f"Found {len(missing_sri)} external script(s) or stylesheet(s) from CDNs "
                "without integrity= attributes. If the CDN is compromised or the resource "
                "is tampered with (supply chain attack), malicious code runs on your site "
                "with full access to your users' sessions and data."
            ),
            evidence=f"Resources missing SRI:\n{examples}",
            remediation=(
                "Add integrity= and crossorigin= attributes to all external scripts/styles. "
                "Use srihash.org to generate the hash."
            ),
            code_fix=(
                "<!-- Generate hash at: https://www.srihash.org/ -->\n\n"
                "<!-- Replace: -->\n"
                "<script src=\"https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js\">\n\n"
                "<!-- With: -->\n"
                "<script\n"
                "  src=\"https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js\"\n"
                "  integrity=\"sha256-/JqT3SQfawRcv/BIHPThkBvs0OEvtFFmqPF/lYI/Cxo=\"\n"
                "  crossorigin=\"anonymous\">"
            ),
            reference="https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity",
            cvss=6.1,
        ))

    return findings
