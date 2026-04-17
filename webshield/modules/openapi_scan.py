"""
OpenAPI / Swagger Spec Import & Endpoint Testing Module (v1.7.0)
Discovers OpenAPI specs, parses all endpoints, tests for unauth access + SQLi.
"""
from __future__ import annotations
import re
import json
from typing import List, Optional, Dict
from urllib.parse import urlparse
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

SPEC_PATHS = [
    "/openapi.json", "/openapi.yaml", "/swagger.json",
    "/swagger/v1/swagger.json", "/api/swagger.json",
    "/api-docs", "/api/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/api/openapi.json", "/api/openapi.yaml",
    "/docs/openapi.json", "/swagger/doc.json",
]

SENSITIVE_PATTERN = re.compile(
    r'"(password|secret|token|api_key|apikey|access_token|private_key)"\s*:', re.I
)
SQL_ERROR = re.compile(
    r"sql syntax|mysql_fetch|ORA-\d+|sqlite_|syntax error.*sql|pg_query", re.I
)


def _parse_spec(text: str) -> Optional[Dict]:
    """Try to parse as JSON. Basic YAML fallback via regex."""
    try:
        return json.loads(text)
    except Exception:
        pass
    # Very basic YAML path extraction via regex (no pyyaml dependency)
    paths = re.findall(r"^\s{2}(/[^\s:]+):", text, re.M)
    if paths:
        return {"paths": {p: {"get": {}} for p in paths}, "_yaml": True}
    return None


def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    parsed   = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    with get_client(timeout=min(timeout, 8.0)) as client:

        # ── 1. Discover spec
        spec      = None
        spec_url  = None
        for path in SPEC_PATHS:
            try:
                r = client.get(base_url + path)
                if r.status_code == 200 and len(r.text) > 50:
                    parsed_spec = _parse_spec(r.text)
                    if parsed_spec and "paths" in parsed_spec:
                        spec     = parsed_spec
                        spec_url = base_url + path
                        break
            except Exception:
                continue

        if not spec:
            return findings

        # Report spec exposure
        findings.append(Finding(
            title=f"OpenAPI/Swagger Spec Publicly Exposed ({spec_url})",
            severity=Severity.MEDIUM,
            description=(
                f"An OpenAPI specification was found at {spec_url}. "
                "This gives attackers a complete map of all API endpoints, "
                "parameters, request/response schemas, and authentication requirements."
            ),
            evidence=f"Spec URL: {spec_url}\nEndpoints found: {len(spec.get('paths', {}))}",
            remediation=(
                "Restrict access to API spec files in production. "
                "If public docs are needed, use a read-only hosted version without live 'Try it out'."
            ),
            code_fix=(
                "# Nginx — block spec in production:\n"
                "location ~* /(openapi|swagger|api-docs) {\n"
                "    deny all;\n"
                "    return 404;\n"
                "}\n\n"
                "# Or gate behind auth:\n"
                "location /openapi.json {\n"
                "    auth_basic 'API Docs';\n"
                "    auth_basic_user_file /etc/nginx/.htpasswd;\n"
                "}"
            ),
            reference="https://owasp.org/www-project-web-security-testing-guide/",
            module="openapi_scan",
            cvss=5.3,
        ))

        # ── 2. Test endpoints
        paths_obj = spec.get("paths", {})
        endpoint_findings = 0

        for api_path, methods in list(paths_obj.items())[:30]:
            if endpoint_findings >= 5:
                break

            for method in list(methods.keys())[:3]:
                if method.startswith("_") or method.lower() not in (
                    "get", "post", "put", "delete", "patch"
                ):
                    continue

                # Build test URL — replace path params with test values
                test_path = re.sub(r"\{[^}]+\}", "1", api_path)
                test_url  = base_url + test_path

                try:
                    if method.lower() == "get":
                        r = client.get(test_url)
                    else:
                        r = client.request(method.upper(), test_url,
                                           headers={"Content-Type": "application/json"},
                                           content=b"{}")
                except Exception:
                    continue

                # Unprotected endpoint
                if r.status_code == 200:
                    sev = Severity.HIGH if any(
                        kw in api_path.lower()
                        for kw in ["admin", "user", "account", "password", "token", "key"]
                    ) else Severity.MEDIUM

                    findings.append(Finding(
                        title=f"Unauthenticated API Endpoint: {method.upper()} {api_path}",
                        severity=sev,
                        description=(
                            f"The API endpoint {method.upper()} {api_path} returns HTTP 200 "
                            "without any authentication. This endpoint was discovered via the "
                            "exposed OpenAPI specification."
                        ),
                        evidence=f"URL: {test_url}\nHTTP {r.status_code}\nResponse: {r.text[:150]}",
                        remediation="Require authentication on all non-public API endpoints.",
                        code_fix=(
                            "# FastAPI:\n"
                            "from fastapi import Depends\n"
                            "from .auth import get_current_user\n\n"
                            f"@app.{method.lower()}('{api_path}')\n"
                            "async def endpoint(user=Depends(get_current_user)):\n"
                            "    ..."
                        ),
                        reference="https://owasp.org/www-project-api-security/",
                        module="openapi_scan",
                        cvss=7.5 if sev == Severity.HIGH else 5.3,
                    ))
                    endpoint_findings += 1

                    # Check for sensitive data in response
                    if SENSITIVE_PATTERN.search(r.text):
                        findings.append(Finding(
                            title=f"Sensitive Data in Unauthenticated API Response: {api_path}",
                            severity=Severity.CRITICAL,
                            description=(
                                f"The unauthenticated endpoint {api_path} returns a response "
                                "containing sensitive field names (password, secret, token, key). "
                                "This likely means credentials or secrets are exposed publicly."
                            ),
                            evidence=f"URL: {test_url}\nSensitive fields found in response: {r.text[:200]}",
                            remediation="Immediately restrict this endpoint and audit what data it returns.",
                            code_fix="# Never return password, secret, or token fields in API responses.\n# Use serializer field exclusions.",
                            reference="https://owasp.org/www-project-api-security/",
                            module="openapi_scan",
                            cvss=9.8,
                        ))
                        endpoint_findings += 1

                # SQLi probe on path params
                if "{" in api_path:
                    sqli_path = re.sub(r"\{[^}]+\}", "1'", api_path)
                    try:
                        rs = client.get(base_url + sqli_path)
                        if SQL_ERROR.search(rs.text):
                            findings.append(Finding(
                                title=f"SQL Injection in API Endpoint: {api_path}",
                                severity=Severity.CRITICAL,
                                description=(
                                    f"SQL injection was detected in the API path parameter of {api_path}. "
                                    "A single quote in the path triggered a database error."
                                ),
                                evidence=f"URL: {base_url + sqli_path}\nSQL error: {rs.text[:200]}",
                                remediation="Use parameterized queries for all database operations.",
                                code_fix="cursor.execute('SELECT * FROM t WHERE id = %s', (path_id,))",
                                reference="https://owasp.org/www-community/attacks/SQL_Injection",
                                module="openapi_scan",
                                cvss=9.8,
                            ))
                            endpoint_findings += 1
                    except Exception:
                        pass

    return findings
