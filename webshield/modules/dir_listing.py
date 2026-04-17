"""
Directory Listing Detection Module
Detects exposed directory listings that allow attackers to enumerate files.
OWASP A02:2025 - Security Misconfiguration
"""

from __future__ import annotations
from typing import List
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

# Directories to probe — mix of common web paths and sensitive locations
PROBE_DIRS = [
    "/",
    "/uploads/",
    "/upload/",
    "/files/",
    "/static/",
    "/assets/",
    "/media/",
    "/images/",
    "/img/",
    "/backup/",
    "/backups/",
    "/bak/",
    "/logs/",
    "/log/",
    "/tmp/",
    "/temp/",
    "/cache/",
    "/data/",
    "/exports/",
    "/downloads/",
    "/storage/",
    "/public/",
    "/css/",
    "/js/",
    "/scripts/",
    "/includes/",
    "/lib/",
    "/vendor/",
    "/node_modules/",
    "/src/",
    "/app/",
    "/config/",
    "/conf/",
    "/etc/",
    "/old/",
    "/archive/",
    "/test/",
    "/tests/",
    "/dev/",
    "/staging/",
    "/api/",
    "/docs/",
    "/swagger/",
    "/migrations/",
]

# Phrases that indicate a real directory listing (across web servers)
LISTING_SIGNATURES = [
    # Apache
    "index of /",
    "directory listing for",
    "parent directory",
    "[to parent directory]",
    # Nginx
    "<title>index of",
    "nginx directory",
    # Python http.server / SimpleHTTP
    "directory listing",
    # IIS
    "dir :",
    # Generic
    "last modified",
    "file listing",
]

# High-risk directory names that make a listing especially dangerous
HIGH_RISK_DIRS = {
    "/backup/", "/backups/", "/bak/", "/logs/", "/log/", "/tmp/", "/temp/",
    "/data/", "/exports/", "/config/", "/conf/", "/etc/", "/old/", "/archive/",
    "/migrations/", "/node_modules/", "/vendor/",
}


def _has_listing_signature(body: str) -> bool:
    """Returns True if the response body looks like a real directory listing."""
    body_lower = body.lower()
    return any(sig in body_lower for sig in LISTING_SIGNATURES)


def _extract_sensitive_files(body: str) -> list:
    """Extract any obviously sensitive filenames visible in the listing."""
    sensitive_extensions = [
        ".sql", ".db", ".sqlite", ".bak", ".backup", ".tar", ".tar.gz",
        ".zip", ".env", ".key", ".pem", ".pfx", ".log", ".conf", ".config",
        ".yml", ".yaml", ".json", ".csv", ".xml", "id_rsa", "private",
    ]
    found = []
    body_lower = body.lower()
    for ext in sensitive_extensions:
        if ext in body_lower:
            found.append(ext)
    return found


def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    base = url.rstrip("/")
    listed_dirs: List[str] = []
    high_risk_listed: List[str] = []

    with get_client(timeout=min(timeout, 8.0)) as client:
        for path in PROBE_DIRS:
            target = base + path
            try:
                resp = client.get(target)

                if resp.status_code != 200:
                    continue

                if len(resp.text.strip()) < 100:
                    continue

                if not _has_listing_signature(resp.text):
                    continue

                listed_dirs.append(path)
                if path in HIGH_RISK_DIRS:
                    high_risk_listed.append(path)

            except Exception:
                continue

    if not listed_dirs:
        return findings

    # Determine overall severity based on what's exposed
    if high_risk_listed:
        severity = Severity.HIGH
        extra = f"\n⚠️  High-risk directories exposed: {', '.join(high_risk_listed)}"
    elif len(listed_dirs) >= 3:
        severity = Severity.MEDIUM
        extra = ""
    else:
        severity = Severity.LOW
        extra = ""

    # Check for sensitive files in the listings (re-fetch to analyze content)
    sensitive_files_found = []
    with get_client(timeout=min(timeout, 6.0)) as client:
        for path in listed_dirs[:5]:  # limit re-fetches
            try:
                resp = client.get(base + path)
                found = _extract_sensitive_files(resp.text)
                if found:
                    sensitive_files_found.extend(
                        [f"{path} → {ext}" for ext in found]
                    )
            except Exception:
                continue

    if sensitive_files_found:
        severity = Severity.HIGH

    evidence_lines = [f"HTTP 200 directory listing at: {base}{p}" for p in listed_dirs]
    if sensitive_files_found:
        evidence_lines.append(f"\nSensitive file types visible: {', '.join(set(sensitive_files_found))}")
    evidence_lines.append(extra)

    findings.append(Finding(
        title=f"Directory Listing Enabled ({len(listed_dirs)} director{'ies' if len(listed_dirs) > 1 else 'y'} exposed)",
        severity=severity,
        description=(
            f"Directory listing is enabled on {len(listed_dirs)} path(s). "
            "Attackers can browse your file system, discover backup files, "
            "configuration files, source code, and other sensitive assets "
            "without any authentication. This is one of the most common and "
            "easily exploited misconfigurations."
        ),
        evidence="\n".join(evidence_lines),
        remediation=(
            "Disable directory listing in your web server configuration. "
            "Ensure no sensitive files are stored in web-accessible directories."
        ),
        code_fix=(
            "# Apache — disable in .htaccess or httpd.conf:\n"
            "Options -Indexes\n\n"
            "# Nginx — remove 'autoindex on' or explicitly deny:\n"
            "location / {\n"
            "    autoindex off;\n"
            "}\n\n"
            "# IIS — disable in web.config:\n"
            '<configuration>\n'
            '  <system.webServer>\n'
            '    <directoryBrowse enabled="false" />\n'
            '  </system.webServer>\n'
            '</configuration>\n\n'
            "# Python (Flask) — never serve static dirs directly in production\n"
            "# Use a reverse proxy (Nginx/Apache) in front of your app server"
        ),
        reference="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
        module="dir_listing",
        cvss=6.5 if severity == Severity.HIGH else 5.3 if severity == Severity.MEDIUM else 3.1,
    ))

    return findings
