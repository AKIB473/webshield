"""ELMAH, Trace.axd, .htaccess & ASP.NET Debug Exposure Module (v1.8.0) — ZAP rules 40028/29/32"""
from __future__ import annotations
import re
from typing import List
from urllib.parse import urlparse
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

CHECKS = [
    ("/elmah.axd",                re.compile(r"ELMAH|Error Log|elmah", re.I),    Severity.HIGH,   7.5,
     "ELMAH Error Log Exposed",
     "The ELMAH (Error Logging Modules and Handlers) error log is publicly accessible. "
     "It contains full exception details, stack traces, form POST data (including passwords), "
     "and server configuration — a goldmine for attackers."),
    ("/trace.axd",                re.compile(r"Application Trace|Request Details|Trace\.axd", re.I), Severity.HIGH, 7.5,
     "ASP.NET Trace.axd Exposed",
     "The ASP.NET application trace viewer is publicly accessible. It shows all HTTP requests "
     "with full headers, form data, cookies, and session variables."),
    ("/.htaccess",                re.compile(r"RewriteRule|Options|AuthType|Require|Allow", re.I), Severity.MEDIUM, 5.3,
     ".htaccess File Exposed",
     "The Apache .htaccess configuration file is readable. It may reveal URL rewrite rules, "
     "authentication configurations, and internal directory structure."),
    ("/.htpasswd",                re.compile(r"[a-zA-Z0-9_\-\.]+:\$(?:apr1|2[ay])\$", re.I), Severity.CRITICAL, 9.1,
     ".htpasswd Password File Exposed",
     "The .htpasswd file containing hashed passwords is publicly accessible. "
     "Attackers can download and crack these hashes offline."),
    ("/web.config",               re.compile(r"<configuration>|<appSettings|<connectionStrings", re.I), Severity.CRITICAL, 9.8,
     "web.config Exposed",
     "The ASP.NET web.config file is readable and may contain database connection strings, "
     "API keys, encryption keys, and other secrets."),
    ("/phpinfo.php",              re.compile(r"PHP Version|phpinfo|php_info", re.I), Severity.HIGH, 7.5,
     "phpinfo() Page Exposed",
     "A phpinfo() page is publicly accessible. It reveals the full PHP configuration, "
     "loaded modules, environment variables, and server paths."),
    ("/info.php",                 re.compile(r"PHP Version|phpinfo", re.I), Severity.HIGH, 7.5,
     "PHP Info Page Exposed (/info.php)",
     "A PHP information page reveals server configuration details."),
    ("/test.php",                 re.compile(r"PHP Version|phpinfo|Test Page", re.I), Severity.MEDIUM, 5.3,
     "PHP Test File Exposed",
     "A PHP test file is accessible in production."),
    ("/WEB-INF/web.xml",          re.compile(r"<web-app|<servlet|<security-constraint", re.I), Severity.HIGH, 8.1,
     "Java WEB-INF/web.xml Exposed",
     "The Java web application descriptor is readable. It reveals servlet mappings, "
     "security constraints, and configuration details."),
    ("/crossdomain.xml",          re.compile(r"allow-access-from|cross-domain-policy", re.I), Severity.MEDIUM, 5.3,
     "Flash crossdomain.xml Exposed (Wildcard Risk)",
     "A crossdomain.xml policy file is accessible. If it allows wildcard origins, "
     "Flash/Silverlight clients can make cross-domain requests."),
    ("/clientaccesspolicy.xml",   re.compile(r"access-policy|allow-from", re.I), Severity.MEDIUM, 5.3,
     "Silverlight clientaccesspolicy.xml Exposed",
     "A Silverlight client access policy file is accessible."),
]

def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    parsed   = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    with get_client(timeout=min(timeout, 8.0)) as client:
        for (path, pattern, severity, cvss, title, desc) in CHECKS:
            try:
                r = client.get(base_url + path)
                if r.status_code == 200 and pattern.search(r.text):
                    findings.append(Finding(
                        title=title,
                        severity=severity,
                        description=desc,
                        evidence=f"URL: {base_url+path}\nHTTP 200\nContent: {r.text[:150].strip()}",
                        remediation=f"Restrict access to {path} via web server configuration or firewall rules.",
                        code_fix=(
                            f"# Nginx:\nlocation ~ {re.escape(path)} {{\n    deny all;\n    return 404;\n}}\n\n"
                            f"# Apache:\n<Files \"{path.lstrip('/')}\">\n    Order allow,deny\n    Deny from all\n</Files>"
                        ),
                        reference="https://owasp.org/www-project-web-security-testing-guide/",
                        module="elmah_trace",
                        cvss=cvss,
                    ))
            except Exception:
                continue
    return findings
