"""
Exposed Admin & Monitoring Panels Module (v1.7.0)
Detects unauthenticated access to admin, monitoring, and infrastructure panels.
"""
from __future__ import annotations
import re
from typing import List
from urllib.parse import urlparse
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

PANELS = [
    ("/jenkins",              re.compile(r"Dashboard|Manage Jenkins|hudson", re.I),           Severity.CRITICAL, "Jenkins CI/CD Panel",           9.8),
    ("/grafana",              re.compile(r"Grafana|grafana",                  re.I),           Severity.CRITICAL, "Grafana Dashboard",             9.8),
    ("/grafana/login",        re.compile(r"Grafana|grafana",                  re.I),           Severity.HIGH,     "Grafana Login Exposed",         7.5),
    ("/kibana",               re.compile(r"Kibana|kibana|elastic",            re.I),           Severity.HIGH,     "Kibana Dashboard",              8.1),
    ("/app/home",             re.compile(r"Kibana|elastic",                   re.I),           Severity.HIGH,     "Kibana App Home",               8.1),
    ("/prometheus",           re.compile(r"Prometheus|prometheus_build",      re.I),           Severity.HIGH,     "Prometheus Metrics UI",         7.5),
    ("/prometheus/targets",   re.compile(r"Targets|scrape",                   re.I),           Severity.HIGH,     "Prometheus Targets Exposed",    7.5),
    ("/_cat/indices",         re.compile(r"health|index|pri|rep",             re.I),           Severity.CRITICAL, "Elasticsearch Indices Exposed", 9.8),
    ("/_cluster/health",      re.compile(r"cluster_name|status",              re.I),           Severity.HIGH,     "Elasticsearch Cluster Health",  7.5),
    ("/portainer",            re.compile(r"Portainer|portainer",              re.I),           Severity.CRITICAL, "Portainer Docker Panel",        9.8),
    ("/dashboard/",           re.compile(r"Traefik|routers|middlewares",      re.I),           Severity.HIGH,     "Traefik Dashboard",             8.1),
    ("/haproxy?stats",        re.compile(r"HAProxy Statistics|pxname",        re.I),           Severity.HIGH,     "HAProxy Stats Exposed",         7.5),
    ("/nginx_status",         re.compile(r"Active connections|server accepts", re.I),          Severity.MEDIUM,   "Nginx Stub Status Exposed",     5.3),
    ("/server-status",        re.compile(r"Apache Status|requests currently", re.I),           Severity.MEDIUM,   "Apache mod_status Exposed",     5.3),
    ("/solr",                 re.compile(r"Solr Admin|solrconfig",            re.I),           Severity.HIGH,     "Apache Solr Admin Exposed",     8.1),
    ("/mongo-express",        re.compile(r"Mongo Express|mongo-express",      re.I),           Severity.CRITICAL, "Mongo Express DB Panel",        9.8),
    ("/rabbitmq",             re.compile(r"RabbitMQ Management",              re.I),           Severity.HIGH,     "RabbitMQ Management UI",        8.1),
    ("/admin/queues",         re.compile(r"RabbitMQ|queue",                   re.I),           Severity.HIGH,     "RabbitMQ Queue Admin",          8.1),
    ("/swagger-ui.html",      re.compile(r"swagger-ui|Swagger UI",            re.I),           Severity.MEDIUM,   "Swagger UI Exposed",            5.3),
    ("/swagger",              re.compile(r"swagger|Swagger",                  re.I),           Severity.MEDIUM,   "Swagger UI Exposed",            5.3),
    ("/api/swagger-ui.html",  re.compile(r"swagger-ui|Swagger UI",            re.I),           Severity.MEDIUM,   "Swagger UI on /api Exposed",    5.3),
    ("/openapi.json",         re.compile(r'"openapi"|"swagger"',              re.I),           Severity.MEDIUM,   "OpenAPI Spec Exposed",          5.3),
    ("/openapi.yaml",         re.compile(r"openapi:|swagger:",                re.I),           Severity.MEDIUM,   "OpenAPI YAML Spec Exposed",     5.3),
    ("/api-docs",             re.compile(r'"paths"|"swagger"',                re.I),           Severity.MEDIUM,   "API Docs Exposed",              5.3),
    ("/.env",                 re.compile(r"DB_PASSWORD|SECRET_KEY|APP_KEY|DATABASE_URL|API_KEY", re.I), Severity.CRITICAL, ".env File With Secrets Exposed", 9.8),
    ("/config.json",          re.compile(r"password|secret|apiKey|db_",       re.I),           Severity.CRITICAL, "config.json With Secrets",      9.8),
    ("/actuator/health",      re.compile(r'"status"\s*:\s*"UP"',              re.I),           Severity.LOW,      "Spring Actuator Health Exposed", 3.1),
    ("/wp-admin/",            re.compile(r"WordPress|wp-admin",               re.I),           Severity.MEDIUM,   "WordPress Admin Panel",         5.3),
    ("/phpmyadmin",           re.compile(r"phpMyAdmin|phpmyadmin",            re.I),           Severity.HIGH,     "phpMyAdmin Exposed",            8.1),
    ("/adminer",              re.compile(r"Adminer|adminer",                  re.I),           Severity.HIGH,     "Adminer DB Panel Exposed",      8.1),
    ("/pgadmin",              re.compile(r"pgAdmin|pgadmin",                  re.I),           Severity.HIGH,     "pgAdmin Exposed",               8.1),
]

FIX_TEMPLATE = (
    "# Nginx — restrict panel access to trusted IPs only:\n"
    "location {path} {{\n"
    "    allow 10.0.0.0/8;\n"
    "    allow 192.168.0.0/16;\n"
    "    deny all;\n"
    "}}\n\n"
    "# Or require authentication:\n"
    "location {path} {{\n"
    "    auth_basic 'Admin Area';\n"
    "    auth_basic_user_file /etc/nginx/.htpasswd;\n"
    "}}"
)


def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    parsed   = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    with get_client(timeout=min(timeout, 8.0)) as client:
        seen_titles = set()
        for (path, pattern, severity, title, cvss) in PANELS:
            try:
                resp = client.get(base_url + path)
                if resp.status_code == 200 and pattern.search(resp.text):
                    if title in seen_titles:
                        continue
                    seen_titles.add(title)
                    findings.append(Finding(
                        title=f"Unauthenticated {title} ({path})",
                        severity=severity,
                        description=(
                            f"The {title} is publicly accessible without authentication at {path}. "
                            "This exposes sensitive operational data and in many cases allows "
                            "full administrative control over the service."
                        ),
                        evidence=f"URL: {base_url + path}\nHTTP 200\nContent: {resp.text[:150].strip()}",
                        remediation=(
                            f"Restrict access to {path} via firewall rules or require authentication. "
                            "This panel should never be accessible from the public internet."
                        ),
                        code_fix=FIX_TEMPLATE.format(path=path),
                        reference="https://owasp.org/www-project-web-security-testing-guide/",
                        module="exposed_panels",
                        cvss=cvss,
                    ))
            except Exception:
                continue

    return findings
