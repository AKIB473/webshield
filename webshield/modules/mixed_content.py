"""
Mixed Content Detection Module (v1.0.1)
Checks for HTTP resources loaded on HTTPS pages (scripts, images, iframes).
"""

from __future__ import annotations
import re
from typing import List
from urllib.parse import urlparse
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client


# Active mixed content (scripts/iframes) = CRITICAL
# Passive mixed content (images/css) = MEDIUM
ACTIVE_PATTERNS = [
    re.compile(r'<script[^>]+src=["\']http://[^"\']+["\']', re.IGNORECASE),
    re.compile(r'<iframe[^>]+src=["\']http://[^"\']+["\']', re.IGNORECASE),
    re.compile(r'<link[^>]+href=["\']http://[^"\']+\.(?:css|js)["\']', re.IGNORECASE),
]

PASSIVE_PATTERNS = [
    re.compile(r'<img[^>]+src=["\']http://[^"\']+["\']', re.IGNORECASE),
    re.compile(r'<video[^>]+src=["\']http://[^"\']+["\']', re.IGNORECASE),
    re.compile(r'<audio[^>]+src=["\']http://[^"\']+["\']', re.IGNORECASE),
    re.compile(r'url\(["\']?http://[^"\')\s]+["\']?\)', re.IGNORECASE),
]


def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    parsed = urlparse(url)

    if parsed.scheme != "https":
        return []  # Mixed content only matters on HTTPS pages

    try:
        with get_client(timeout=timeout) as client:
            resp = client.get(url)
    except Exception:
        return []

    body = resp.text
    active_found = []
    passive_found = []

    for pattern in ACTIVE_PATTERNS:
        matches = pattern.findall(body)
        active_found.extend(matches[:3])  # Cap at 3 examples

    for pattern in PASSIVE_PATTERNS:
        matches = pattern.findall(body)
        passive_found.extend(matches[:3])

    if active_found:
        findings.append(Finding(
            title="Active Mixed Content Detected",
            severity=Severity.HIGH,
            description=(
                "Active mixed content (scripts, iframes, or stylesheets) is being "
                "loaded over HTTP on an HTTPS page. Browsers block this in modern "
                "versions, breaking your site. Worse, if somehow allowed, an attacker "
                "on the network can inject malicious code into your HTTPS page."
            ),
            evidence="HTTP resources found:\n" + "\n".join(
                f"  {m[:100]}" for m in active_found[:3]
            ),
            remediation="Change all src/href attributes to use https:// or protocol-relative URLs (//).",
            code_fix=(
                "<!-- Replace: -->\n"
                "<script src=\"http://cdn.example.com/app.js\">\n\n"
                "<!-- With: -->\n"
                "<script src=\"https://cdn.example.com/app.js\">\n"
                "<!-- or: -->\n"
                "<script src=\"//cdn.example.com/app.js\">"
            ),
            reference="https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content",
            cvss=6.5,
        ))

    if passive_found:
        findings.append(Finding(
            title="Passive Mixed Content Detected (Images/Media over HTTP)",
            severity=Severity.LOW,
            description=(
                "Images, video, or audio are being loaded over HTTP on an HTTPS page. "
                "While browsers usually allow this, it leaks the user's HTTPS browsing "
                "to passive network observers and may trigger browser warnings."
            ),
            evidence="HTTP resources found:\n" + "\n".join(
                f"  {m[:100]}" for m in passive_found[:3]
            ),
            remediation="Update all resource URLs to use https://.",
            code_fix=(
                "<!-- Replace: -->\n"
                "<img src=\"http://example.com/image.png\">\n\n"
                "<!-- With: -->\n"
                "<img src=\"https://example.com/image.png\">"
            ),
            reference="https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content",
        ))

    # Check for upgrade-insecure-requests CSP directive
    csp_header = resp.headers.get("content-security-policy", "")
    if not active_found and not passive_found and "upgrade-insecure-requests" not in csp_header.lower():
        findings.append(Finding(
            title="CSP upgrade-insecure-requests Not Set",
            severity=Severity.INFO,
            description=(
                "The 'upgrade-insecure-requests' CSP directive is not set. "
                "This directive automatically upgrades HTTP resource requests to HTTPS, "
                "preventing accidental mixed content."
            ),
            evidence="upgrade-insecure-requests not in Content-Security-Policy",
            remediation="Add upgrade-insecure-requests to your CSP header.",
            code_fix=(
                "Content-Security-Policy: upgrade-insecure-requests; default-src 'self';\n\n"
                "# Nginx:\n"
                "add_header Content-Security-Policy \"upgrade-insecure-requests; ...\" always;"
            ),
            reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/upgrade-insecure-requests",
        ))

    return findings
