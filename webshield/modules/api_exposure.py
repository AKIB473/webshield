"""
API Exposure & Endpoint Discovery Module
Discovers exposed API docs, OpenAPI/Swagger specs, and sensitive API endpoints.
OWASP A02:2025 - Security Misconfiguration | A01:2025 - Broken Access Control
"""

from __future__ import annotations
from typing import List
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

# (path, title, severity, description, confirm_keywords)
API_PATHS = [
    # OpenAPI / Swagger
    ("/swagger.json",           "OpenAPI Spec Exposed (swagger.json)",      Severity.MEDIUM,
     "The raw OpenAPI/Swagger specification is publicly accessible. Reveals all API endpoints, parameters, authentication methods, and data models to attackers.",
     ["swagger", "openapi", "paths", "info"]),
    ("/openapi.json",           "OpenAPI Spec Exposed (openapi.json)",       Severity.MEDIUM,
     "OpenAPI specification file exposed. Attackers use this to map every endpoint and understand the full API surface.",
     ["openapi", "paths", "info", "components"]),
    ("/openapi.yaml",           "OpenAPI Spec Exposed (openapi.yaml)",       Severity.MEDIUM,
     "OpenAPI YAML specification is publicly accessible.",
     ["openapi", "paths", "info"]),
    ("/swagger.yaml",           "Swagger YAML Spec Exposed",                 Severity.MEDIUM,
     "Swagger YAML spec is publicly accessible.",
     ["swagger", "paths", "info"]),
    ("/swagger-ui.html",        "Swagger UI Exposed",                        Severity.MEDIUM,
     "Interactive Swagger UI is publicly accessible. Allows anyone to explore and test all API endpoints directly from the browser.",
     ["swagger", "swaggerui", "swagger-ui"]),
    ("/swagger-ui/",            "Swagger UI Exposed",                        Severity.MEDIUM,
     "Swagger UI interface is publicly accessible.",
     ["swagger"]),
    ("/api/swagger.json",       "API Swagger Spec Exposed",                  Severity.MEDIUM,
     "Swagger API spec exposed under /api path.",
     ["swagger", "openapi", "paths"]),
    ("/api/openapi.json",       "API OpenAPI Spec Exposed",                  Severity.MEDIUM,
     "OpenAPI spec exposed under /api path.",
     ["openapi", "paths"]),
    ("/api-docs",               "API Documentation Exposed",                 Severity.MEDIUM,
     "API documentation endpoint is publicly accessible.",
     ["api", "endpoint", "swagger", "openapi", "routes"]),
    ("/api-docs/",              "API Documentation Exposed",                 Severity.MEDIUM,
     "API docs directory accessible.",
     ["api", "swagger"]),
    ("/api/docs",               "API Docs Exposed",                          Severity.MEDIUM,
     "API documentation accessible at /api/docs.",
     ["api", "docs", "swagger", "endpoint"]),
    ("/v1/api-docs",            "API v1 Docs Exposed",                       Severity.MEDIUM,
     "Versioned API documentation is publicly accessible.",
     ["api", "paths", "swagger"]),
    ("/v2/api-docs",            "API v2 Docs Exposed",                       Severity.MEDIUM,
     "API v2 Swagger documentation exposed.",
     ["api", "paths", "swagger"]),
    ("/v3/api-docs",            "API v3 Docs Exposed",                       Severity.MEDIUM,
     "API v3 OpenAPI documentation exposed.",
     ["api", "paths", "openapi"]),

    # GraphQL
    ("/graphql",                "GraphQL Endpoint Exposed",                  Severity.MEDIUM,
     "GraphQL endpoint is publicly accessible. Without proper authorization, attackers can query any data using introspection.",
     ["data", "errors", "__schema"]),
    ("/graphiql",               "GraphiQL IDE Exposed",                      Severity.HIGH,
     "GraphiQL interactive IDE is publicly accessible. Allows full query execution and schema introspection without authentication.",
     ["graphiql", "graphql", "query"]),
    ("/altair",                 "Altair GraphQL Client Exposed",             Severity.MEDIUM,
     "Altair GraphQL client interface is publicly accessible.",
     ["altair", "graphql"]),
    ("/api/graphql",            "GraphQL API Endpoint Exposed",              Severity.MEDIUM,
     "GraphQL API endpoint accessible.",
     ["data", "errors"]),

    # Admin & internal APIs
    ("/api/v1/users",           "User List API Exposed",                     Severity.HIGH,
     "User listing API endpoint is accessible without authentication. May expose PII including emails, usernames, and user IDs.",
     ["user", "email", "id", "username", "name"]),
    ("/api/v1/admin",           "Admin API Exposed",                         Severity.CRITICAL,
     "Admin API endpoint is publicly accessible. May allow unauthorized admin operations.",
     ["admin", "user", "config", "setting"]),
    ("/api/admin",              "Admin API Exposed",                         Severity.CRITICAL,
     "Admin API endpoint accessible without authentication.",
     ["admin", "user", "config"]),
    ("/api/v1/config",          "Config API Exposed",                        Severity.HIGH,
     "Configuration API endpoint accessible. May expose system settings and credentials.",
     ["config", "setting", "key", "secret", "database"]),
    ("/api/v1/settings",        "Settings API Exposed",                      Severity.HIGH,
     "Settings API endpoint accessible.",
     ["setting", "config", "value"]),
    ("/api/internal",           "Internal API Exposed",                      Severity.HIGH,
     "Internal API endpoint is publicly accessible. Not intended for public consumption.",
     ["internal", "api", "data"]),
    ("/api/private",            "Private API Exposed",                       Severity.HIGH,
     "Private API endpoint is publicly accessible.",
     ["private", "api", "data"]),

    # Debug / health endpoints
    ("/api/health",             "API Health Endpoint Exposed",               Severity.INFO,
     "API health check endpoint is publicly accessible. May reveal service names, versions, or dependency status.",
     ["health", "status", "ok", "up", "database"]),
    ("/api/status",             "API Status Endpoint Exposed",               Severity.INFO,
     "API status endpoint accessible. Reveals service state information.",
     ["status", "ok", "version", "uptime"]),
    ("/api/version",            "API Version Endpoint Exposed",              Severity.INFO,
     "API version endpoint reveals the application version to attackers.",
     ["version", "build", "release"]),
    ("/api/metrics",            "API Metrics Exposed",                       Severity.MEDIUM,
     "API metrics endpoint accessible. May expose performance data, request counts, and internal timings.",
     ["metric", "counter", "gauge", "histogram"]),
    ("/metrics",                "Prometheus Metrics Exposed",                Severity.MEDIUM,
     "Prometheus metrics endpoint is publicly accessible. Exposes internal system metrics and service details.",
     ["# HELP", "# TYPE", "http_requests", "go_"]),
    ("/healthz",                "Kubernetes Health Endpoint Exposed",        Severity.INFO,
     "Kubernetes-style health endpoint accessible.",
     ["ok", "healthy", "status"]),
    ("/readyz",                 "Kubernetes Readiness Endpoint Exposed",     Severity.INFO,
     "Kubernetes readiness probe endpoint accessible.",
     ["ok", "ready"]),
]


def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    base = url.rstrip("/")

    with get_client(timeout=min(timeout, 8.0)) as client:
        for path, title, severity, description, confirm_keywords in API_PATHS:
            target = base + path
            try:
                resp = client.get(
                    target,
                    headers={"Accept": "application/json, text/html, */*"},
                )

                if resp.status_code == 401:
                    # Endpoint exists but requires auth — still worth noting for critical/high
                    if severity in (Severity.CRITICAL, Severity.HIGH):
                        findings.append(Finding(
                            title=f"{title} (Auth Required)",
                            severity=Severity.LOW,
                            description=f"{description} Authentication is enforced but endpoint is reachable.",
                            evidence=f"HTTP 401 at {target}",
                            remediation="Verify the endpoint is intentionally exposed and authentication is strong.",
                            module="api_exposure",
                        ))
                    continue

                if resp.status_code not in (200, 403):
                    continue

                if resp.status_code == 403:
                    if severity == Severity.CRITICAL:
                        findings.append(Finding(
                            title=f"{title} (Forbidden — Endpoint Exists)",
                            severity=Severity.LOW,
                            description=f"{description} Access is currently forbidden but the endpoint exists.",
                            evidence=f"HTTP 403 at {target}",
                            remediation="Ensure access controls are robust and monitor for bypass attempts.",
                            module="api_exposure",
                        ))
                    continue

                # Must have real content
                if len(resp.text.strip()) < 30:
                    continue

                # Confirm with keywords
                body_lower = resp.text.lower()
                content_type = resp.headers.get("content-type", "").lower()

                # Accept if JSON content-type (strong signal) or keywords match
                is_json = "application/json" in content_type or "application/yaml" in content_type
                keyword_match = any(kw.lower() in body_lower for kw in confirm_keywords)

                if not (is_json or keyword_match):
                    continue

                # Estimate data sensitivity
                has_pii = any(kw in body_lower for kw in
                              ["email", "password", "secret", "token", "api_key",
                               "apikey", "credential", "private_key"])
                if has_pii and severity.value in ("MEDIUM", "LOW"):
                    severity = Severity.HIGH

                findings.append(Finding(
                    title=title,
                    severity=severity,
                    description=description,
                    evidence=(
                        f"HTTP {resp.status_code} at {target}\n"
                        f"Content-Type: {content_type}\n"
                        f"Response size: {len(resp.content)} bytes"
                    ),
                    remediation=(
                        "Restrict access to API documentation and internal endpoints. "
                        "Use authentication (API keys, OAuth) and IP allowlisting for admin APIs. "
                        "Disable Swagger UI and GraphiQL in production environments."
                    ),
                    code_fix=(
                        "# Nginx — block in production:\n"
                        f"location ~* ^{path} {{\n"
                        "    # Allow only internal IPs:\n"
                        "    allow 10.0.0.0/8;\n"
                        "    deny all;\n}}\n\n"
                        "# Or disable Swagger in Spring Boot:\n"
                        "# spring.swagger-ui.enabled=false  (application.properties)\n\n"
                        "# Disable GraphiQL in production:\n"
                        "# graphql.graphiql.enabled=false"
                    ),
                    reference="https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
                    module="api_exposure",
                    cvss=7.5 if severity == Severity.HIGH else 5.3 if severity == Severity.MEDIUM else 9.8,
                ))

            except Exception:
                continue

    return findings
