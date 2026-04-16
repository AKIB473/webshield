"""
Information Leakage Module
Checks for exposed .env, .git, backup files, debug pages, and secrets.
Learned from: Greaper (CVE scanner), GSEC, w4af (find_dvcs, find_backdoors), Wapiti (mod_backup)
"""

from __future__ import annotations
import re
from typing import List
import httpx
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

# (path, title, severity, description, remediation)
SENSITIVE_PATHS = [
    # Git / VCS
    ("/.git/config",       "Exposed Git Repository",       Severity.CRITICAL,
     "The .git directory is publicly accessible. Attackers can download your entire source code, "
     "including hardcoded credentials, API keys, and internal logic.",
     "Block access to .git in your web server config.",
     "# Nginx:\nlocation ~ /\\.git { deny all; return 404; }\n\n# Apache:\n<DirectoryMatch \\.(git|svn)>\n  Require all denied\n</DirectoryMatch>"),

    ("/.svn/entries",      "Exposed SVN Repository",       Severity.CRITICAL,
     "Subversion repository files are publicly accessible. Full source code may be recoverable.",
     "Block .svn access at the web server level.",
     "# Nginx:\nlocation ~ /\\.svn { deny all; }"),

    # Environment / Config files
    ("/.env",              "Exposed .env File",            Severity.CRITICAL,
     "The .env file is publicly accessible. This file typically contains database passwords, "
     "API keys, secret keys, and other sensitive credentials.",
     "Move .env outside the web root or block access via web server config.",
     "# Nginx:\nlocation ~ /\\.env { deny all; return 404; }\n\n# .htaccess:\n<Files .env>\n  Order allow,deny\n  Deny from all\n</Files>"),

    ("/.env.production",   "Exposed .env.production File", Severity.CRITICAL,
     "Production environment file is publicly accessible, likely containing live credentials.",
     "Block all dot-files from being served publicly.",
     "location ~ /\\. { deny all; }"),

    ("/.env.local",        "Exposed .env.local File",      Severity.CRITICAL,
     "Local environment file is publicly accessible.",
     "Block all dotfiles at the web server level.",
     "location ~ /\\. { deny all; }"),

    # Backup files
    ("/backup.zip",        "Backup Archive Exposed",       Severity.CRITICAL,
     "A backup archive is publicly accessible. May contain full source code and configuration.",
     "Remove backup files from the web root. Store them in a non-public location.",
     "rm /var/www/html/backup.zip  # then store backups outside web root"),

    ("/backup.tar.gz",     "Backup Archive Exposed",       Severity.CRITICAL,
     "A .tar.gz backup is publicly accessible.",
     "Remove backup files from the web root.",
     "rm /var/www/html/backup.tar.gz"),

    ("/db.sql",            "SQL Dump Exposed",             Severity.CRITICAL,
     "A SQL database dump is publicly accessible. Contains all your database data.",
     "Remove SQL dumps from the web root immediately.",
     "rm /var/www/html/db.sql"),

    ("/dump.sql",          "SQL Dump Exposed",             Severity.CRITICAL,
     "A database dump file is publicly accessible.",
     "Remove database dumps from the web root.",
     "rm /var/www/html/dump.sql"),

    # Debug / Info pages
    ("/phpinfo.php",       "PHP Info Page Exposed",        Severity.HIGH,
     "phpinfo() exposes PHP version, loaded modules, server paths, and configuration values. "
     "Attackers use this to find exploitable configurations.",
     "Delete phpinfo.php from production servers immediately.",
     "rm /var/www/html/phpinfo.php"),

    ("/info.php",          "PHP Info Page Exposed",        Severity.HIGH,
     "phpinfo() page is accessible.",
     "Delete info.php from production servers.",
     "rm /var/www/html/info.php"),

    ("/server-status",     "Apache Server Status Exposed", Severity.MEDIUM,
     "Apache mod_status is publicly accessible, revealing active connections, requests, and worker status.",
     "Restrict /server-status to localhost only.",
     "# Apache:\n<Location /server-status>\n  Require local\n</Location>"),

    ("/server-info",       "Apache Server Info Exposed",   Severity.MEDIUM,
     "Apache server-info page leaks loaded modules, configuration files, and settings.",
     "Restrict or disable server-info.",
     "# Apache:\n<Location /server-info>\n  Require local\n</Location>"),

    # Composer / Package files
    ("/composer.json",     "Composer Config Exposed",      Severity.MEDIUM,
     "composer.json reveals exact dependency versions, helping attackers find vulnerable packages.",
     "Block access to composer files in web server config.",
     "location ~ /composer\\.(json|lock) { deny all; }"),

    ("/composer.lock",     "Composer Lock File Exposed",   Severity.MEDIUM,
     "composer.lock reveals exact package versions with potential known CVEs.",
     "Block access to composer.lock.",
     "location ~ /composer\\.lock { deny all; }"),

    ("/package.json",      "package.json Exposed",         Severity.LOW,
     "package.json reveals Node.js dependencies and may expose internal project structure.",
     "Block access to package.json in production.",
     "location ~ /package\\.json { deny all; }"),

    # Logs
    ("/error.log",         "Error Log Exposed",            Severity.HIGH,
     "Application error logs are publicly accessible. May contain stack traces, file paths, and credentials.",
     "Move log files outside the web root.",
     "# Store logs in /var/log/ not in web root"),

    ("/access.log",        "Access Log Exposed",           Severity.MEDIUM,
     "Web server access logs are publicly accessible, revealing all user activity.",
     "Move log files outside the web root.",
     "# Store logs in /var/log/ not in web root"),

    # Kubernetes / Cloud
    ("/.kube/config",      "Kubernetes Config Exposed",    Severity.CRITICAL,
     "Kubernetes configuration file exposed. Contains cluster credentials and API endpoint.",
     "Remove .kube from web root. Never store config files in public directories.",
     "location ~ /\\.kube { deny all; }"),

    ("/docker-compose.yml", "Docker Compose Config Exposed", Severity.HIGH,
     "docker-compose.yml may reveal service architecture, ports, and environment variables.",
     "Block docker-compose.yml from being served.",
     "location ~ /docker-compose { deny all; }"),
]

# Patterns that indicate actual sensitive content (reduce false positives)
CONTENT_PATTERNS = {
    "/.git/config":    r"\[core\]",
    "/.env":           r"(DB_|APP_|API_|SECRET|PASSWORD|TOKEN|KEY)\s*=",
    "/.env.production":r"(DB_|APP_|API_|SECRET|PASSWORD|TOKEN|KEY)\s*=",
    "/.env.local":     r"(DB_|APP_|API_|SECRET|PASSWORD|TOKEN|KEY)\s*=",
    "/phpinfo.php":    r"phpinfo\(\)",
    "/info.php":       r"phpinfo\(\)",
}


def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    base = url.rstrip("/")

    with get_client(timeout=timeout) as client:
        for (path, title, severity, description, remediation, code_fix) in SENSITIVE_PATHS:
            target = base + path
            try:
                resp = client.get(target)

                # Must be 200 and not a generic error page
                if resp.status_code != 200:
                    continue

                # For some paths, check content matches expected pattern
                content_check = CONTENT_PATTERNS.get(path)
                if content_check:
                    if not re.search(content_check, resp.text, re.IGNORECASE):
                        continue

                # Must have non-trivial content
                if len(resp.text.strip()) < 10:
                    continue

                findings.append(Finding(
                    title=title,
                    severity=severity,
                    description=description,
                    evidence=f"HTTP 200 at {target} — Content length: {len(resp.content)} bytes",
                    remediation=remediation,
                    code_fix=code_fix,
                    reference="https://owasp.org/www-project-web-security-testing-guide/",
                    cvss=9.8 if severity == Severity.CRITICAL else 7.5,
                ))

            except Exception:
                continue

    return findings
