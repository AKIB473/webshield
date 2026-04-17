"""
Source Code Disclosure Module (v1.6.0)
Detects exposed version control repositories, backup files, and source code.
Inspired by: Nikto db_tests (git/svn/backup checks), ZAP rules 41/42/43

Checks:
- .git/HEAD fetchable (entire repo downloadable with git clone)
- .svn/entries / .svn/wc.db exposed
- .hg/hgrc (Mercurial repo)
- Backup source files (.php.bak, .php~, .php.old, .bak, .orig)
- Source map files (.js.map -> leaks original pre-minified source)
- Editor swap files (.swp, .swo -- vim leftovers with source)
- composer.json / package.json / requirements.txt exposed
- Web.config / application.yml / .env.example exposed
"""

from __future__ import annotations
import re
from typing import List
from urllib.parse import urlparse
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

GIT_HEAD_PATTERN    = re.compile(r"^ref:\s*refs/heads/|^[0-9a-f]{40}", re.M)
SVN_ENTRIES_PATTERN = re.compile(r"<wc-entries|dir\s*\d+\s*\d+", re.I)
HG_PATTERN          = re.compile(r"\[paths\]|\[ui\]", re.I)
SOURCE_MAP_PATTERN  = re.compile(r'"sources"\s*:\s*\[', re.I)
PHP_SOURCE_PATTERN  = re.compile(r"<\?php|\$[a-zA-Z_]\w*\s*=", re.I)
CONFIG_PATTERN      = re.compile(
    r"(password|secret|db_|database_url|api_key|token)\s*[=:]", re.I
)

VCS_PATHS = [
    ("/.git/HEAD",        GIT_HEAD_PATTERN,    "CRITICAL",
     "Git Repository Exposed (/.git/HEAD)",
     "The .git directory is publicly accessible. Attackers can use "
     "`git clone` to download the entire source code including all "
     "commit history, secrets committed in the past, and credentials.",
     9.8,
     "# Nginx — block .git access:\n"
     "location ~ /\\.git {\n    deny all;\n    return 404;\n}\n\n"
     "# Apache .htaccess:\n"
     "RedirectMatch 404 /\\.git"),

    ("/.git/config",      re.compile(r"\[core\]|\[remote", re.I), "HIGH",
     "Git Config Exposed (/.git/config)",
     "The Git config file leaks repository origin URLs, potentially "
     "revealing internal infrastructure hostnames or auth tokens.",
     7.5,
     "location ~ /\\.git { deny all; return 404; }"),

    ("/.svn/entries",     SVN_ENTRIES_PATTERN, "HIGH",
     "SVN Repository Exposed (/.svn/entries)",
     "The Subversion .svn directory is publicly accessible, allowing "
     "attackers to download source files and history via svn export.",
     8.1,
     "location ~ /\\.svn { deny all; return 404; }"),

    ("/.svn/wc.db",       re.compile(r"REPOSITORY|NODES", re.I), "HIGH",
     "SVN Working Copy Database Exposed (/.svn/wc.db)",
     "The SVN working copy database is publicly readable, exposing "
     "all versioned file paths and potentially file contents.",
     8.1,
     "location ~ /\\.svn { deny all; return 404; }"),

    ("/.hg/hgrc",         HG_PATTERN, "HIGH",
     "Mercurial Repository Exposed (/.hg/hgrc)",
     "The Mercurial .hg directory is publicly accessible, allowing "
     "attackers to clone the repository via `hg clone`.",
     8.1,
     "location ~ /\\.hg { deny all; return 404; }"),
]

BACKUP_EXTENSIONS = [
    ".bak", ".old", ".orig", ".backup", ".copy",
    ".php.bak", ".php~", ".php.old", ".php.orig",
    ".asp.bak", ".asp~", ".aspx.bak",
    ".jsp.bak", ".py.bak", ".rb.bak",
    ".swp", ".swo",   # vim swap files
]

CONFIG_EXPOSURE_PATHS = [
    ("/composer.json",       re.compile(r'"require"\s*:', re.I),       "MEDIUM",
     "Composer Dependencies Exposed",
     "composer.json lists all PHP dependencies and versions, enabling "
     "attackers to find components with known CVEs.",
     5.3),
    ("/package.json",        re.compile(r'"dependencies"\s*:', re.I),  "MEDIUM",
     "NPM Package Manifest Exposed",
     "package.json lists all Node.js dependencies and versions. "
     "Attackers can identify outdated packages with known CVEs.",
     5.3),
    ("/requirements.txt",    re.compile(r'\w+[>=<]=?\d', re.I),        "MEDIUM",
     "Python Requirements Exposed",
     "requirements.txt reveals Python package names and versions, "
     "allowing CVE targeting of outdated dependencies.",
     4.3),
    ("/.env.example",        CONFIG_PATTERN,                            "MEDIUM",
     "Environment Config Example Exposed (.env.example)",
     ".env.example may reveal expected secret names, key formats, "
     "and infrastructure hostnames even without real values.",
     4.3),
    ("/web.config.bak",      re.compile(r"<configuration>|appSettings", re.I), "HIGH",
     "Web.config Backup Exposed",
     "A web.config backup file is accessible. It may contain "
     "database connection strings, API keys, and encryption keys.",
     8.1),
    ("/application.yml",     CONFIG_PATTERN,                            "HIGH",
     "Spring Boot application.yml Exposed",
     "The Spring Boot application.yml may contain database credentials, "
     "JWT secrets, and cloud provider keys.",
     8.1),
    ("/config/database.yml", CONFIG_PATTERN,                            "CRITICAL",
     "Rails Database Config Exposed (config/database.yml)",
     "The Rails database.yml file is publicly accessible. It contains "
     "database credentials for all environments.",
     9.8),
    ("/Dockerfile",          re.compile(r"FROM\s+\w|ENV\s+\w", re.I),  "MEDIUM",
     "Dockerfile Exposed",
     "The Dockerfile reveals base image, build steps, and may expose "
     "ARG/ENV values including credentials baked into the image.",
     4.3),
    ("/docker-compose.yml",  re.compile(r"image:|services:", re.I),    "MEDIUM",
     "Docker Compose File Exposed",
     "docker-compose.yml reveals service architecture, image names, "
     "port mappings, and potentially environment variable secrets.",
     5.3),
]


def _get_base_files(url: str) -> List[str]:
    """Extract the page's file path to check for backup variants."""
    parsed = urlparse(url)
    path = parsed.path
    # Only consider paths that look like files (have extension or specific names)
    if "." in path.split("/")[-1]:
        return [path]
    return []


def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    parsed   = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    with get_client(timeout=min(timeout, 8.0)) as client:

        # ── 1. VCS repository exposure
        for (path, pattern, sev_str, title, desc, cvss, fix) in VCS_PATHS:
            try:
                resp = client.get(base_url + path)
                if resp.status_code == 200 and pattern.search(resp.text):
                    findings.append(Finding(
                        title=title,
                        severity=Severity(sev_str),
                        description=desc,
                        evidence=f"URL: {base_url + path}\nHTTP 200\nContent: {resp.text[:120].strip()}",
                        remediation="Block all VCS directory access at the web server level.",
                        code_fix=fix,
                        reference="https://portswigger.net/web-security/information-disclosure",
                        module="source_code_disclosure",
                        cvss=cvss,
                    ))
                    break  # one VCS finding is enough
            except Exception:
                continue

        # ── 2. Source map exposure (leaks pre-minified JS source)
        try:
            resp = client.get(url)
            if resp.status_code == 200:
                # Look for SourceMappingURL comment in JS files
                smap_refs = re.findall(
                    r"//[#@]\s*sourceMappingURL=([^\s]+\.map)", resp.text
                )
                for smap in smap_refs[:2]:
                    map_url = (
                        smap if smap.startswith("http")
                        else base_url + "/" + smap.lstrip("/")
                    )
                    try:
                        mr = client.get(map_url)
                        if mr.status_code == 200 and SOURCE_MAP_PATTERN.search(mr.text):
                            findings.append(Finding(
                                title="Source Map File Exposed — Pre-Minified Source Leaked",
                                severity=Severity.HIGH,
                                description=(
                                    "A JavaScript source map (.map) file is publicly accessible. "
                                    "Source maps contain the original, unminified source code including "
                                    "comments, variable names, file structure, and logic — "
                                    "dramatically lowering the bar for reverse engineering."
                                ),
                                evidence=f"Source map URL: {map_url}\nSources array found in map file.",
                                remediation=(
                                    "Remove SourceMappingURL comments from production JS bundles, "
                                    "or restrict .map file access to internal networks only."
                                ),
                                code_fix=(
                                    "# Webpack — disable source maps in production:\n"
                                    "// webpack.config.js\n"
                                    "module.exports = {\n"
                                    "  devtool: process.env.NODE_ENV === 'production'\n"
                                    "    ? false  // no source maps in prod\n"
                                    "    : 'eval-source-map',\n"
                                    "}\n\n"
                                    "# Or restrict in Nginx:\n"
                                    "location ~* \\.map$ {\n"
                                    "    deny all;\n"
                                    "    return 404;\n"
                                    "}"
                                ),
                                reference="https://developer.chrome.com/docs/devtools/javascript/source-maps/",
                                module="source_code_disclosure",
                                cvss=6.5,
                            ))
                            break
                    except Exception:
                        continue
        except Exception:
            pass

        # ── 3. Backup source file variants of the current page
        page_path = parsed.path.rstrip("/") or "/index"
        if not page_path.endswith(tuple(BACKUP_EXTENSIONS)):
            for ext in BACKUP_EXTENSIONS[:8]:  # focus on most common
                backup_path = page_path + ext
                try:
                    resp = client.get(base_url + backup_path)
                    if resp.status_code == 200 and len(resp.content) > 50:
                        body = resp.text[:300]
                        is_source = (
                            PHP_SOURCE_PATTERN.search(body) or
                            "<?php" in body or
                            body.strip().startswith("<%") or
                            CONFIG_PATTERN.search(body)
                        )
                        if is_source:
                            findings.append(Finding(
                                title=f"Source Code Backup File Exposed ({backup_path})",
                                severity=Severity.HIGH,
                                description=(
                                    f"A backup copy of the source file is publicly accessible at "
                                    f"{backup_path}. It contains raw server-side source code "
                                    "which may include credentials, business logic, and SQL queries."
                                ),
                                evidence=f"URL: {base_url + backup_path}\nHTTP 200\nContent: {body[:150]}",
                                remediation=(
                                    "Delete all backup files from the web root. "
                                    "Configure the web server to deny access to backup extensions."
                                ),
                                code_fix=(
                                    "# Nginx — block backup extensions:\n"
                                    "location ~* \\.(bak|old|orig|backup|swp|swo)$ {\n"
                                    "    deny all;\n"
                                    "    return 404;\n"
                                    "}\n\n"
                                    "# Apache .htaccess:\n"
                                    '<FilesMatch "\\.(bak|old|orig|backup|swp|swo)$">\n'
                                    "    Order allow,deny\n"
                                    "    Deny from all\n"
                                    "</FilesMatch>"
                                ),
                                reference="https://owasp.org/www-project-web-security-testing-guide/",
                                module="source_code_disclosure",
                                cvss=7.5,
                            ))
                            break
                except Exception:
                    continue

        # ── 4. Config / manifest file exposure
        for (path, pattern, sev_str, title, desc, cvss) in CONFIG_EXPOSURE_PATHS:
            try:
                resp = client.get(base_url + path)
                if resp.status_code == 200 and pattern.search(resp.text):
                    findings.append(Finding(
                        title=title,
                        severity=Severity(sev_str),
                        description=desc,
                        evidence=f"URL: {base_url + path}\nHTTP 200\nContent: {resp.text[:200].strip()}",
                        remediation="Block public access to configuration and manifest files.",
                        code_fix=(
                            "# Nginx:\n"
                            "location ~* \\.(json|yml|yaml|xml|config|cfg|conf)$ {\n"
                            "    deny all;\n"
                            "    return 404;\n"
                            "}"
                        ),
                        reference="https://owasp.org/www-project-web-security-testing-guide/",
                        module="source_code_disclosure",
                        cvss=cvss,
                    ))
            except Exception:
                continue

    return findings
