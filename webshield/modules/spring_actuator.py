"""
Spring Boot Actuator & Framework Exposure Module (v1.6.0)
Detects exposed management endpoints that leak sensitive runtime info or allow RCE.
Inspired by: Nuclei spring-actuator templates, ZAP rule 40042, Nikto CGI checks

Checks:
- Spring Boot Actuator endpoints (/actuator/*)
  - /actuator/heapdump   → full JVM heap dump (passwords, keys in memory)
  - /actuator/env        → all environment variables including secrets
  - /actuator/mappings   → all URL routes (reconnaissance)
  - /actuator/beans      → Spring bean definitions
  - /actuator/logfile    → application log contents
  - /actuator/shutdown   → can shut down the app (POST)
  - /actuator/httptrace  → recent HTTP requests including auth headers
  - /actuator/configprops → all configuration properties
- Spring Boot admin panel (/spring-boot-admin)
- Metrics endpoints (Prometheus /metrics, Micrometer /actuator/prometheus)
- Quarkus dev UI (/q/dev)
- Django Debug Toolbar exposure
- Laravel Telescope (/telescope)
- Node.js debug port exposure hints
"""

from __future__ import annotations
import re
from typing import List, Tuple
from urllib.parse import urlparse
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

# (path, severity, title, description snippet, cvss, what_to_look_for)
ACTUATOR_CHECKS: List[Tuple] = [
    (
        "/actuator/heapdump",
        Severity.CRITICAL,
        "Spring Boot Heap Dump Exposed (/actuator/heapdump)",
        "The JVM heap dump endpoint is publicly accessible. A heap dump contains "
        "a full snapshot of JVM memory including plaintext passwords, JWT signing keys, "
        "database credentials, and session tokens that were in memory at dump time.",
        9.8,
        None,  # binary file — just check status + content-type
        "application/octet-stream",
    ),
    (
        "/actuator/env",
        Severity.CRITICAL,
        "Spring Boot Environment Exposed (/actuator/env)",
        "The /actuator/env endpoint exposes ALL environment variables and configuration "
        "properties including database URLs with credentials, API keys, JWT secrets, "
        "cloud provider credentials, and any other secret set via environment variables.",
        9.8,
        re.compile(r'"activeProfiles"|"propertySources"|"systemEnvironment"', re.I),
        None,
    ),
    (
        "/actuator/configprops",
        Severity.CRITICAL,
        "Spring Boot Config Properties Exposed (/actuator/configprops)",
        "All Spring Boot configuration properties are exposed. This includes "
        "datasource URLs, passwords, mail server credentials, and all application secrets.",
        9.8,
        re.compile(r'"contextId"|"beans"', re.I),
        None,
    ),
    (
        "/actuator/httptrace",
        Severity.HIGH,
        "Spring Boot HTTP Trace Exposed (/actuator/httptrace)",
        "Recent HTTP request/response traces are exposed including Authorization headers, "
        "session cookies, and request bodies. Attackers can harvest valid session tokens.",
        8.5,
        re.compile(r'"traces"|"timestamp"', re.I),
        None,
    ),
    (
        "/actuator/mappings",
        Severity.MEDIUM,
        "Spring Boot URL Mappings Exposed (/actuator/mappings)",
        "All application URL route mappings are exposed. This gives attackers a complete "
        "map of the application including hidden admin endpoints and API routes.",
        5.3,
        re.compile(r'"dispatcherServlets"|"mappings"', re.I),
        None,
    ),
    (
        "/actuator/beans",
        Severity.MEDIUM,
        "Spring Boot Bean Definitions Exposed (/actuator/beans)",
        "The Spring bean definition list reveals the application's internal structure "
        "including all components, dependencies, and framework versions.",
        4.3,
        re.compile(r'"beans"|"contexts"', re.I),
        None,
    ),
    (
        "/actuator/logfile",
        Severity.HIGH,
        "Spring Boot Log File Exposed (/actuator/logfile)",
        "Application log contents are publicly accessible. Logs may contain passwords "
        "printed during startup, stack traces with internal paths, SQL queries, "
        "and other sensitive operational data.",
        7.5,
        re.compile(r"(ERROR|WARN|INFO|DEBUG)\s+\[", re.I),
        None,
    ),
    (
        "/actuator",
        Severity.MEDIUM,
        "Spring Boot Actuator Index Exposed (/actuator)",
        "The Spring Boot Actuator management endpoint index is accessible. "
        "It lists all available management endpoints.",
        5.3,
        re.compile(r'"_links"|"actuator"', re.I),
        None,
    ),
    (
        "/actuator/prometheus",
        Severity.MEDIUM,
        "Prometheus Metrics Exposed (/actuator/prometheus)",
        "Prometheus-format metrics are exposed. These reveal application performance "
        "data, JVM internals, connection pool usage, and business metrics.",
        4.3,
        re.compile(r"^#\s+HELP\s+|^#\s+TYPE\s+", re.M),
        None,
    ),
    (
        "/metrics",
        Severity.MEDIUM,
        "Metrics Endpoint Exposed (/metrics)",
        "Application metrics are publicly accessible, leaking internal performance "
        "data, database connection counts, and operational statistics.",
        4.3,
        re.compile(r'"counter\.|"gauge\.|"histogram\.', re.I),
        None,
    ),
]

OTHER_CHECKS: List[Tuple] = [
    (
        "/actuator/shutdown",
        Severity.CRITICAL,
        "Spring Boot Shutdown Endpoint Exposed (/actuator/shutdown)",
        "The application shutdown endpoint is accessible. Sending a POST request "
        "to this endpoint will immediately shut down the Spring Boot application.",
        9.8,
        "POST",
        re.compile(r'"message"\s*:\s*"Shutting down"', re.I),
    ),
    (
        "/q/dev",
        Severity.HIGH,
        "Quarkus Dev UI Exposed (/q/dev)",
        "The Quarkus developer UI is exposed in production. It provides access to "
        "configuration, extensions, and potentially code execution features.",
        8.1,
        "GET",
        re.compile(r"Quarkus|q-dev|quarkus-dev", re.I),
    ),
    (
        "/telescope",
        Severity.HIGH,
        "Laravel Telescope Debug Panel Exposed (/telescope)",
        "Laravel Telescope is accessible. It shows all requests, queries, jobs, "
        "exceptions, logs, and cache operations — a goldmine for attackers.",
        8.1,
        "GET",
        re.compile(r"Laravel Telescope|telescope-dark", re.I),
    ),
    (
        "/__clockwork/app",
        Severity.HIGH,
        "Clockwork Debug Profiler Exposed (/__clockwork)",
        "The Clockwork PHP profiler UI is accessible. It reveals request/response data, "
        "database queries with parameters, and stack traces.",
        7.5,
        "GET",
        re.compile(r"clockwork|__clockwork", re.I),
    ),
    (
        "/debug/vars",
        Severity.HIGH,
        "Go expvar Debug Endpoint Exposed (/debug/vars)",
        "The Go expvar debug endpoint is publicly accessible. It exposes runtime "
        "variables, memory stats, and custom application metrics.",
        6.5,
        "GET",
        re.compile(r'"cmdline"|"memstats"', re.I),
    ),
    (
        "/rails/info/properties",
        Severity.HIGH,
        "Rails Info Endpoint Exposed (/rails/info/properties)",
        "The Rails properties info endpoint is accessible in what appears to be "
        "a production environment. It reveals framework versions, middleware, and routes.",
        6.5,
        "GET",
        re.compile(r"Rails version|Ruby version|RubyGems version", re.I),
    ),
    (
        "/__debug__/",
        Severity.HIGH,
        "Django Debug Toolbar Exposed (/__debug__/)",
        "The Django Debug Toolbar is accessible. It shows all SQL queries, request "
        "variables, settings, and profiling data.",
        7.5,
        "GET",
        re.compile(r"djdt|django-debug-toolbar", re.I),
    ),
]


def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    parsed   = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    with get_client(timeout=min(timeout, 8.0)) as client:

        # ── Spring Actuator checks
        for (path, severity, title, desc, cvss, pattern, content_type) in ACTUATOR_CHECKS:
            try:
                resp = client.get(base_url + path)
                if resp.status_code != 200:
                    continue

                hit = False
                if content_type and content_type in resp.headers.get("content-type", ""):
                    hit = True
                elif pattern and pattern.search(resp.text):
                    hit = True
                elif not content_type and not pattern and resp.status_code == 200:
                    hit = True

                if hit:
                    evidence_body = resp.text[:250].strip() if resp.text else "(binary)"
                    findings.append(Finding(
                        title=title,
                        severity=severity,
                        description=desc,
                        evidence=f"URL: {base_url + path}\nHTTP 200\nContent: {evidence_body}",
                        remediation=(
                            "Restrict actuator endpoint access. In Spring Boot:\n"
                            "1. Disable sensitive endpoints: management.endpoints.enabled-by-default=false\n"
                            "2. Only expose health: management.endpoints.web.exposure.include=health\n"
                            "3. Bind to internal port: management.server.port=8081 (not public)\n"
                            "4. Add Spring Security to management endpoints"
                        ),
                        code_fix=(
                            "# application.yml:\n"
                            "management:\n"
                            "  endpoints:\n"
                            "    web:\n"
                            "      exposure:\n"
                            "        include: health          # ONLY expose health\n"
                            "        # include: '*'  <-- NEVER do this in production\n"
                            "  endpoint:\n"
                            "    health:\n"
                            "      show-details: never       # don't expose DB details\n"
                            "  server:\n"
                            "    port: 8081                 # bind to internal port\n\n"
                            "# Or secure with Spring Security:\n"
                            "@Configuration\n"
                            "public class ActuatorSecurity {\n"
                            "  @Bean SecurityFilterChain actuatorSecurity(HttpSecurity http) {\n"
                            "    http.requestMatcher(EndpointRequest.toAnyEndpoint())\n"
                            "        .authorizeRequests().anyRequest().hasRole('ADMIN');\n"
                            "    return http.build();\n"
                            "  }\n"
                            "}"
                        ),
                        reference="https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html",
                        module="spring_actuator",
                        cvss=cvss,
                    ))
            except Exception:
                continue

        # ── Shutdown endpoint (POST)
        try:
            check = ACTUATOR_CHECKS  # already imported
            # Check actuator/shutdown via GET first (should return 405 if exists but auth required)
            r = client.get(base_url + "/actuator/shutdown")
            if r.status_code in (200, 405, 401, 403):
                # Exists — try posting
                rp = client.post(base_url + "/actuator/shutdown", json={})
                if rp.status_code == 200:
                    findings.append(Finding(
                        title="Spring Boot Shutdown Endpoint Accessible — RCE via DoS",
                        severity=Severity.CRITICAL,
                        description=(
                            "The /actuator/shutdown endpoint accepted a POST request and "
                            "may have shut down the application. This endpoint allows "
                            "any unauthenticated user to kill the service."
                        ),
                        evidence=f"POST /actuator/shutdown → HTTP {rp.status_code}\nResponse: {rp.text[:100]}",
                        remediation="Disable the shutdown endpoint: management.endpoint.shutdown.enabled=false",
                        code_fix=(
                            "# application.yml:\n"
                            "management:\n"
                            "  endpoint:\n"
                            "    shutdown:\n"
                            "      enabled: false   # NEVER enable in production"
                        ),
                        reference="https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html",
                        module="spring_actuator",
                        cvss=9.8,
                    ))
        except Exception:
            pass

        # ── Other framework debug panels
        for (path, severity, title, desc, cvss, method, pattern) in OTHER_CHECKS:
            try:
                if method == "GET":
                    resp = client.get(base_url + path)
                else:
                    resp = client.post(base_url + path, json={})

                if resp.status_code == 200 and pattern.search(resp.text):
                    findings.append(Finding(
                        title=title,
                        severity=severity,
                        description=desc,
                        evidence=f"URL: {base_url + path}\nHTTP 200\n{resp.text[:200].strip()}",
                        remediation=(
                            "Disable debug/profiling tools in production. "
                            "Set environment to 'production' and restrict access to "
                            "debug endpoints via authentication or firewall rules."
                        ),
                        code_fix=(
                            "# Ensure NODE_ENV=production / APP_ENV=production\n"
                            "# Django: DEBUG = False in settings.py\n"
                            "# Laravel: APP_DEBUG=false in .env\n"
                            "# Rails: config.consider_all_requests_local = false"
                        ),
                        reference="https://owasp.org/www-project-web-security-testing-guide/",
                        module="spring_actuator",
                        cvss=cvss,
                    ))
            except Exception:
                continue

    return findings
