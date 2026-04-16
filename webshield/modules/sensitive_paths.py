"""
Sensitive Path Exposure Module
Checks for exposed admin panels, default login pages, debug interfaces.
Learned from: GSEC (dirbrutescanner), w4af (find_backdoors), Wapiti (mod_nikto), yawast-ng
"""

from __future__ import annotations
from typing import List
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

SENSITIVE_PATHS = [
    # Admin panels
    ("/admin",           "Admin Panel Exposed",          Severity.MEDIUM, "Default admin panel accessible."),
    ("/admin/login",     "Admin Login Exposed",          Severity.MEDIUM, "Admin login page is publicly accessible."),
    ("/administrator",   "Joomla Admin Exposed",         Severity.MEDIUM, "Default Joomla admin path accessible."),
    ("/wp-admin",        "WordPress Admin Exposed",      Severity.MEDIUM, "WordPress admin panel accessible. Ensure strong password and 2FA."),
    ("/wp-login.php",    "WordPress Login Exposed",      Severity.LOW,    "WordPress login page accessible. Brute force risk."),
    ("/phpmyadmin",      "phpMyAdmin Exposed",           Severity.HIGH,   "phpMyAdmin database management tool is publicly accessible. Extremely dangerous."),
    ("/phpmyadmin/",     "phpMyAdmin Exposed",           Severity.HIGH,   "phpMyAdmin is publicly accessible."),
    ("/pma",             "phpMyAdmin Exposed (pma)",     Severity.HIGH,   "phpMyAdmin accessible via /pma."),
    ("/db",              "Database Interface Exposed",   Severity.HIGH,   "Possible database management interface exposed."),
    ("/adminer.php",     "Adminer DB Tool Exposed",      Severity.HIGH,   "Adminer database tool is publicly accessible."),
    ("/adminer",         "Adminer DB Tool Exposed",      Severity.HIGH,   "Adminer database tool accessible."),
    # Debug / Dev tools
    ("/_profiler",       "Symfony Profiler Exposed",     Severity.HIGH,   "Symfony debug profiler exposes request data, config, and database queries."),
    ("/debug",           "Debug Interface Exposed",      Severity.HIGH,   "A debug interface is publicly accessible."),
    ("/debug/pprof",     "Go pprof Debug Exposed",       Severity.HIGH,   "Go pprof profiling endpoint accessible publicly. Exposes memory dumps."),
    ("/actuator",        "Spring Boot Actuator Exposed", Severity.HIGH,   "Spring Boot Actuator endpoints exposed. May allow RCE via /actuator/env or /actuator/restart."),
    ("/actuator/env",    "Spring Boot Actuator /env",    Severity.CRITICAL,"Spring Boot /actuator/env exposes all environment variables including secrets."),
    ("/actuator/shutdown","Spring Boot Actuator Shutdown",Severity.CRITICAL,"Spring Boot /actuator/shutdown allows remote application shutdown."),
    ("/console",         "Web Console Exposed",          Severity.HIGH,   "Web admin console is accessible."),
    ("/rails/info",      "Rails Info Exposed",           Severity.MEDIUM, "Rails info page exposes routes and configuration."),
    ("/__clockwork",     "Clockwork Debugbar Exposed",   Severity.MEDIUM, "Laravel Clockwork debug data exposed."),
    ("/telescope",       "Laravel Telescope Exposed",    Severity.MEDIUM, "Laravel Telescope debug dashboard is publicly accessible."),
    ("/horizon",         "Laravel Horizon Exposed",      Severity.MEDIUM, "Laravel Horizon queue dashboard is accessible."),
    # CI/CD & Monitoring
    ("/jenkins",         "Jenkins CI Exposed",           Severity.HIGH,   "Jenkins CI server is publicly accessible."),
    ("/grafana",         "Grafana Dashboard Exposed",    Severity.MEDIUM, "Grafana monitoring dashboard is publicly accessible."),
    ("/kibana",          "Kibana Exposed",               Severity.HIGH,   "Kibana log analytics dashboard accessible. May expose sensitive log data."),
    # Config files
    ("/config.php",      "Config File Exposed",          Severity.HIGH,   "PHP config file is publicly accessible. May contain DB credentials."),
    ("/config.yml",      "Config YAML Exposed",          Severity.HIGH,   "YAML configuration file is accessible."),
    ("/config.json",     "Config JSON Exposed",          Severity.HIGH,   "JSON configuration file is accessible."),
    ("/web.config",      "ASP.NET web.config Exposed",   Severity.HIGH,   "ASP.NET web.config may contain database connection strings and secrets."),
    ("/settings.py",     "Django Settings Exposed",      Severity.CRITICAL,"Django settings.py is publicly accessible. Contains SECRET_KEY and DB credentials."),
    # API docs
    ("/api/swagger",     "Swagger UI Exposed",           Severity.LOW,    "Swagger API documentation is publicly accessible. May expose internal API structure."),
    ("/swagger-ui.html", "Swagger UI Exposed",           Severity.LOW,    "Swagger UI accessible."),
    ("/api-docs",        "API Docs Exposed",             Severity.LOW,    "API documentation is publicly accessible."),
    ("/graphql",         "GraphQL Endpoint Found",       Severity.INFO,   "GraphQL endpoint found. Will be analyzed further."),
]

CONFIRM_CONTENT = {
    "/phpmyadmin":       ["phpmyadmin", "mysql", "database"],
    "/wp-admin":         ["wordpress", "wp-admin", "dashboard"],
    "/actuator":         ["links", "health", "info"],
    "/actuator/env":     ["activeProfiles", "propertySources"],
    "/jenkins":          ["jenkins", "build", "pipeline"],
    "/grafana":          ["grafana", "dashboard", "login"],
    "/swagger-ui.html":  ["swagger", "openapi", "api"],
    "/__clockwork":      ["clockwork", "timeline"],
}


def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    base = url.rstrip("/")

    with get_client(timeout=timeout) as client:
        for path, title, severity, description in SENSITIVE_PATHS:
            target = base + path
            try:
                resp = client.get(target)

                if resp.status_code not in (200, 401, 403):
                    continue

                # For 401/403 — still interesting (endpoint exists)
                if resp.status_code in (401, 403):
                    if severity in (Severity.CRITICAL, Severity.HIGH):
                        findings.append(Finding(
                            title=f"{title} (Auth Required)",
                            severity=Severity.LOW,
                            description=f"{description} Authentication is required but the endpoint exists.",
                            evidence=f"HTTP {resp.status_code} at {target}",
                            remediation="Verify this path is intentionally exposed and properly secured.",
                        ))
                    continue

                # For 200 — verify content if we have a check
                content_checks = CONFIRM_CONTENT.get(path, [])
                body_lower = resp.text.lower()
                if content_checks:
                    if not any(kw in body_lower for kw in content_checks):
                        continue

                # Must not be a generic 404 page with 200 status
                if len(resp.text.strip()) < 50:
                    continue

                findings.append(Finding(
                    title=title,
                    severity=severity,
                    description=description,
                    evidence=f"HTTP 200 at {target} ({len(resp.content)} bytes)",
                    remediation=(
                        "Restrict access to this path using IP allowlisting, "
                        "authentication, or by removing it from public web root."
                    ),
                    code_fix=(
                        "# Nginx — restrict to specific IP:\n"
                        f"location {path} {{\n"
                        "    allow 192.168.1.0/24;  # your office IP\n"
                        "    deny all;\n}}"
                    ),
                    reference="https://owasp.org/www-project-web-security-testing-guide/",
                    cvss=9.8 if severity == Severity.CRITICAL else 7.5 if severity == Severity.HIGH else 5.3,
                ))

            except Exception:
                continue

    return findings
