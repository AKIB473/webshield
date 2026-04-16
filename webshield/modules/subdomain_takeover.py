"""
Subdomain Takeover Module
Checks if subdomains point to unclaimed 3rd party services.
Learned from: Wapiti (mod_takeover), yawast-ng (subdomains)
"""

from __future__ import annotations
import re
from typing import List
from urllib.parse import urlparse
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

# (service_name, cname_pattern, fingerprint_in_body, description)
TAKEOVER_FINGERPRINTS = [
    ("GitHub Pages",      r"github\.io",           "There isn't a GitHub Pages site here",
     "GitHub Pages site unclaimed — attacker can create a repo and host malicious content."),
    ("Heroku",            r"herokuapp\.com",        "No such app",
     "Heroku app doesn't exist — attacker can claim this app name and serve content."),
    ("AWS S3",            r"s3\.amazonaws\.com",    "NoSuchBucket|The specified bucket does not exist",
     "S3 bucket doesn't exist — attacker can create this bucket and serve content."),
    ("AWS CloudFront",    r"cloudfront\.net",       "ERROR: The request could not be satisfied",
     "CloudFront distribution misconfigured or deleted."),
    ("Fastly",            r"fastly\.net",           "Fastly error: unknown domain",
     "Fastly service not configured for this domain."),
    ("Netlify",           r"netlify\.app|netlify\.com", "Not Found — Request ID",
     "Netlify site unclaimed for this subdomain."),
    ("Shopify",           r"myshopify\.com",        "Sorry, this shop is currently unavailable",
     "Shopify store is not active — subdomain takeover possible."),
    ("Tumblr",            r"tumblr\.com",           "Whatever you were looking for doesn't currently exist",
     "Tumblr account deleted or never created for this subdomain."),
    ("Zendesk",           r"zendesk\.com",          "Help Center Closed",
     "Zendesk subdomain is unclaimed."),
    ("Surge.sh",          r"surge\.sh",             "project not found",
     "Surge.sh project not deployed — takeover possible."),
    ("Readme.io",         r"readme\.io",            "Project doesnt exist",
     "Readme.io documentation site is unclaimed."),
    ("HelpJuice",         r"helpjuice\.com",        "We could not find what you're looking for",
     "HelpJuice knowledge base is unclaimed."),
    ("Cargo",             r"cargocollective\.com",  "404 Not Found",
     "Cargo Collective site is unclaimed."),
    ("Bitbucket",         r"bitbucket\.io",         "Repository not found",
     "Bitbucket Pages site is unclaimed."),
    ("Azure",             r"azurewebsites\.net|cloudapp\.azure\.com", "404 Web Site not found",
     "Azure web app or cloud service is deleted but DNS still points to it."),
]

COMMON_SUBDOMAINS = [
    "www", "mail", "blog", "dev", "staging", "api", "app", "portal",
    "status", "help", "support", "docs", "cdn", "static", "assets",
    "beta", "test", "demo", "shop", "store",
]


def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []

    if not DNS_AVAILABLE:
        return []

    parsed = urlparse(url)
    base_domain = parsed.hostname
    if not base_domain:
        return []

    # Strip www to get root domain
    root = re.sub(r"^www\.", "", base_domain)

    # Check common subdomains
    subdomains_to_check = [f"{sub}.{root}" for sub in COMMON_SUBDOMAINS]
    subdomains_to_check.append(base_domain)

    with get_client(timeout=timeout) as client:
        for subdomain in subdomains_to_check:
            # Check CNAME records
            try:
                answers = dns.resolver.resolve(subdomain, "CNAME", lifetime=5)
                for rdata in answers:
                    cname_target = str(rdata.target).lower()

                    for (service, cname_pattern, body_fingerprint, description) in TAKEOVER_FINGERPRINTS:
                        if re.search(cname_pattern, cname_target, re.IGNORECASE):
                            # Try to fetch and check for fingerprint
                            try:
                                sub_url = f"https://{subdomain}"
                                resp = client.get(sub_url)
                                body = resp.text

                                if re.search(body_fingerprint, body, re.IGNORECASE):
                                    findings.append(Finding(
                                        title=f"Subdomain Takeover Risk: {subdomain} → {service}",
                                        severity=Severity.HIGH,
                                        description=(
                                            f"{description}\n\n"
                                            f"The subdomain {subdomain} has a CNAME pointing to "
                                            f"{cname_target} ({service}), but the service "
                                            "doesn't have a site configured for this domain. "
                                            "An attacker can claim this service and serve malicious content "
                                            "from your subdomain."
                                        ),
                                        evidence=(
                                            f"Subdomain: {subdomain}\n"
                                            f"CNAME: {cname_target}\n"
                                            f"Service: {service}\n"
                                            f"Response fingerprint matched: {body_fingerprint}"
                                        ),
                                        remediation=(
                                            f"Either claim the {service} service for this subdomain, "
                                            "or remove the CNAME DNS record if the service is no longer used."
                                        ),
                                        reference="https://github.com/EdOverflow/can-i-take-over-xyz",
                                        cvss=8.1,
                                    ))
                            except Exception:
                                pass
            except Exception:
                continue

    return findings
