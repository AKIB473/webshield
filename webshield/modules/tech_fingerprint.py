"""
Technology Fingerprinting & CVE Detection Module
Detects frameworks, CMS, servers, and maps them to known CVEs.
Learned from: Greaper (version detection), GSEC (techscanner), Wapiti (mod_wapp), yawast-ng
"""

from __future__ import annotations
import re
from typing import List, Dict, Optional, Tuple
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

# (regex_pattern, framework_name, header_to_check)
# header_to_check: "headers", "body", "both"
TECH_PATTERNS: List[Tuple[str, str, str]] = [
    # Servers
    (r"Apache/(\d+\.\d+[\.\d]*)",          "Apache",         "headers"),
    (r"nginx/(\d+\.\d+[\.\d]*)",            "nginx",          "headers"),
    (r"Microsoft-IIS/(\d+\.\d+)",           "IIS",            "headers"),
    (r"LiteSpeed",                           "LiteSpeed",      "headers"),
    (r"cloudflare",                          "Cloudflare",     "headers"),
    # Languages / Runtimes
    (r"PHP/(\d+\.\d+[\.\d]*)",              "PHP",            "headers"),
    (r"Python/(\d+\.\d+[\.\d]*)",           "Python",         "headers"),
    # Frameworks
    (r"Django/(\d+\.\d+[\.\d]*)",           "Django",         "headers"),
    (r"Laravel v?(\d+\.\d+[\.\d]*)",        "Laravel",        "body"),
    (r"Express",                             "Express.js",     "headers"),
    (r"Ruby on Rails (\d+\.\d+[\.\d]*)",    "Ruby on Rails",  "body"),
    (r"Spring-Boot/(\d+\.\d+[\.\d]*)",      "Spring Boot",    "headers"),
    (r"ASP\.NET",                            "ASP.NET",        "headers"),
    # CMS
    (r"WordPress/(\d+\.\d+[\.\d]*)",        "WordPress",      "both"),
    (r"wp-content|wp-includes",             "WordPress",      "body"),
    (r"Joomla[! ](\d+\.\d+[\.\d]*)?",      "Joomla",         "both"),
    (r"Drupal (\d+\.\d+[\.\d]*)?",          "Drupal",         "both"),
    (r"Shopify",                             "Shopify",        "body"),
    (r"Magento",                             "Magento",        "body"),
    (r"typo3",                               "TYPO3",          "body"),
    # JS Frameworks (from meta/scripts)
    (r"react(?:\.min)?\.js",                "React",          "body"),
    (r"vue(?:\.min)?\.js",                  "Vue.js",         "body"),
    (r"angular(?:\.min)?\.js",             "Angular",         "body"),
    (r"next\.js",                           "Next.js",        "body"),
    # Databases (from errors)
    (r"MySQL",                              "MySQL",           "body"),
    (r"PostgreSQL",                         "PostgreSQL",      "body"),
    (r"ORA-\d{5}",                          "Oracle DB",       "body"),
    (r"Microsoft SQL Server",               "MSSQL",           "body"),
]

# Known vulnerable versions: (tech, max_safe_version, cve, description, cvss)
VULNERABLE_VERSIONS: List[Tuple[str, str, str, str, float]] = [
    ("PHP",        "8.0",  "CVE-2021-21707",  "PHP < 8.0 has multiple critical vulnerabilities including null byte injection.", 7.5),
    ("PHP",        "7.4",  "CVE-2019-11043",  "PHP-FPM 7.x remote code execution via nginx misconfig.", 9.8),
    ("Apache",     "2.4.51","CVE-2021-42013", "Apache 2.4.49/2.4.50 path traversal and RCE.", 9.8),
    ("Apache",     "2.4.49","CVE-2021-41773", "Apache 2.4.49 path traversal vulnerability (actively exploited).", 7.5),
    ("nginx",      "1.20", "CVE-2021-23017",  "nginx < 1.20.1 DNS resolver off-by-one heap write.", 7.7),
    ("WordPress",  "6.3",  "CVE-2023-2745",   "WordPress < 6.3 path traversal vulnerability.", 5.4),
    ("WordPress",  "6.0",  "CVE-2022-21663",  "WordPress < 6.0 authenticated SQL injection.", 7.4),
    ("Drupal",     "9.3",  "CVE-2022-25271",  "Drupal < 9.3.x critical access bypass.", 8.8),
    ("Joomla",     "4.2",  "CVE-2023-23752",  "Joomla < 4.2.8 unauthenticated information disclosure.", 7.5),
    ("Laravel",    "9.0",  "CVE-2021-3129",   "Laravel < 9 debug mode RCE via Ignition.", 9.8),
    ("Spring Boot","2.6",  "CVE-2022-22965",  "Spring4Shell — Spring Framework RCE (CVE-2022-22965).", 9.8),
    ("IIS",        "10.0", "CVE-2017-7269",   "IIS 6.0 WebDAV remote buffer overflow.", 9.8),
]


def _version_less_than(detected: str, threshold: str) -> bool:
    """Compare version strings numerically."""
    try:
        det = [int(x) for x in detected.split(".")[:3]]
        thr = [int(x) for x in threshold.split(".")[:3]]
        return det < thr
    except Exception:
        return False


def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []

    try:
        with get_client(timeout=timeout) as client:
            resp = client.get(url)
    except Exception as e:
        return []

    headers_str = str(dict(resp.headers))
    body_str    = resp.text
    both_str    = headers_str + " " + body_str

    detected: Dict[str, str] = {}  # tech → version

    for (pattern, tech, check_in) in TECH_PATTERNS:
        target_str = {"headers": headers_str, "body": body_str, "both": both_str}.get(check_in, both_str)
        match = re.search(pattern, target_str, re.IGNORECASE)
        if match:
            version = match.group(1) if match.lastindex and match.lastindex >= 1 else "unknown"
            if tech not in detected:
                detected[tech] = version
                findings.append(Finding(
                    title=f"Technology Detected: {tech}" + (f" {version}" if version != "unknown" else ""),
                    severity=Severity.INFO,
                    description=f"Identified {tech}" + (f" version {version}" if version != "unknown" else "") + " from response.",
                    evidence=f"Detected via {'headers' if check_in == 'headers' else 'page content'}",
                    remediation=(
                        "Ensure this technology is kept up to date. "
                        "Consider hiding version numbers from response headers to reduce information disclosure."
                    ),
                    reference=f"https://www.cvedetails.com/vendor-search.php?vendor={tech.replace(' ', '+')}",
                ))

    # CVE version checks
    for (tech, max_safe, cve, description, cvss) in VULNERABLE_VERSIONS:
        if tech in detected and detected[tech] != "unknown":
            version = detected[tech]
            if _version_less_than(version, max_safe):
                findings.append(Finding(
                    title=f"Known Vulnerable Version: {tech} {version} ({cve})",
                    severity=Severity.CRITICAL if cvss >= 9.0 else Severity.HIGH if cvss >= 7.0 else Severity.MEDIUM,
                    description=description,
                    evidence=f"Detected: {tech} {version}\nVulnerable until: {max_safe}\nCVSS: {cvss}",
                    remediation=f"Update {tech} to version {max_safe} or later immediately.",
                    code_fix=(
                        f"# Update {tech}:\n"
                        f"# Check: https://nvd.nist.gov/vuln/detail/{cve}"
                    ),
                    reference=f"https://nvd.nist.gov/vuln/detail/{cve}",
                    cvss=cvss,
                ))

    # Check for version disclosure in Server header (even without CVE match)
    server_header = resp.headers.get("server", "")
    if re.search(r"\d+\.\d+", server_header):
        findings.append(Finding(
            title="Server Version Disclosed in Header",
            severity=Severity.LOW,
            description=(
                f"The Server header reveals version information: '{server_header}'. "
                "This helps attackers identify specific vulnerable versions."
            ),
            evidence=f"Server: {server_header}",
            remediation="Configure your web server to hide version numbers.",
            code_fix=(
                "# Nginx:\nserver_tokens off;\n\n"
                "# Apache:\nServerTokens Prod\nServerSignature Off"
            ),
            reference="https://owasp.org/www-project-web-security-testing-guide/",
        ))

    return findings
