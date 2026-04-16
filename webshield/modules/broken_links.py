"""
Broken Links & Dead Assets Module (v1.2.0)
Finds 404/broken external links, dead social profiles, abandoned subdomains.
Learned from: GSEC (broken_links.py — includes social platform checking)
"""
from __future__ import annotations
import re
from typing import List, Set
from urllib.parse import urlparse, urljoin
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

LINK_PATTERN = re.compile(
    r'<a[^>]+href\s*=\s*["\']([^"\'#\s][^"\']*)["\']',
    re.I
)

SOCIAL_PLATFORMS = [
    "instagram.com", "facebook.com", "twitter.com", "x.com",
    "linkedin.com", "youtube.com", "github.com", "tiktok.com",
]


def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    parsed = urlparse(url)
    base_domain = parsed.netloc

    try:
        with get_client(timeout=min(timeout, 8.0)) as client:
            resp = client.get(url)
    except Exception:
        return []

    body = resp.text
    links: Set[str] = set()

    for match in LINK_PATTERN.finditer(body):
        href = match.group(1).strip()
        if href.startswith(("mailto:", "tel:", "javascript:", "#")):
            continue
        if href.startswith("http"):
            links.add(href)
        elif href.startswith("/"):
            links.add(f"{parsed.scheme}://{base_domain}{href}")
        else:
            links.add(urljoin(url, href))

    if not links:
        return []

    broken: List[str] = []
    social_broken: List[str] = []

    # Test up to 20 links
    with get_client(timeout=5.0) as client:
        for link in list(links)[:20]:
            try:
                resp = client.get(link, follow_redirects=True)
                link_domain = urlparse(link).netloc.lower()

                if resp.status_code == 404:
                    if any(sp in link_domain for sp in SOCIAL_PLATFORMS):
                        social_broken.append(link)
                    else:
                        broken.append(link)
                elif resp.status_code in (410, 451):
                    broken.append(link)
            except Exception:
                broken.append(link)

    if social_broken:
        findings.append(Finding(
            title=f"Broken Social Media Links ({len(social_broken)}) — Subdomain Takeover Risk",
            severity=Severity.MEDIUM,
            description=(
                f"Found {len(social_broken)} broken social media link(s). "
                "If these profiles were abandoned, attackers may register the username "
                "and impersonate your brand on social platforms."
            ),
            evidence="Broken social links:\n" + "\n".join(f"  - {l}" for l in social_broken[:5]),
            remediation=(
                "Either update the links to active profiles or remove them. "
                "If profiles were abandoned, consider reclaiming the usernames."
            ),
            reference="https://owasp.org/www-project-web-security-testing-guide/",
        ))

    if len(broken) >= 3:
        findings.append(Finding(
            title=f"Multiple Broken Links Found ({len(broken)})",
            severity=Severity.INFO,
            description=(
                f"Found {len(broken)} broken link(s) returning 404/error. "
                "Beyond UX issues, broken links to external resources that "
                "have been re-registered by others could be a security risk."
            ),
            evidence="Sample broken links:\n" + "\n".join(f"  - {l}" for l in broken[:5]),
            remediation="Audit and fix or remove broken links.",
            reference="https://developers.google.com/search/docs/crawling-indexing/fix-search-errors",
        ))

    return findings
