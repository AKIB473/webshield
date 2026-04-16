"""
GraphQL Security Module — UNIQUE, nobody else has this as a standalone pip tool
Tests introspection, DoS, CSRF, and common misconfigs.
Learned from: GSEC (graphql_security.py — most complete GraphQL scanner found)
"""

from __future__ import annotations
import json
from typing import List, Optional
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

GRAPHQL_ENDPOINTS = [
    "/graphql", "/graphql/", "/api/graphql", "/api/graphql/",
    "/v1/graphql", "/v2/graphql", "/gql", "/query",
    "/graphiql", "/api/v1/graphql",
]

INTROSPECTION_QUERY = '{"query":"{ __schema { types { name } } }"}'
BATCH_QUERY = '[{"query":"{ __typename }"},{"query":"{ __typename }"},{"query":"{ __typename }"}]'
DEEP_QUERY = '{"query":"{ a:__schema{types{fields{type{fields{type{fields{type{name}}}}}}}}}"}'


def _find_graphql(base: str, client) -> Optional[str]:
    for path in GRAPHQL_ENDPOINTS:
        try:
            resp = client.post(
                base + path,
                content=INTROSPECTION_QUERY,
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code == 200:
                body = resp.text
                if '"data"' in body or '"errors"' in body or '"__schema"' in body:
                    return base + path
        except Exception:
            continue
    return None


def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    base = url.rstrip("/")

    with get_client(timeout=timeout) as client:

        # 1. Discover GraphQL endpoint
        gql_url = _find_graphql(base, client)
        if not gql_url:
            return []

        findings.append(Finding(
            title="GraphQL Endpoint Discovered",
            severity=Severity.INFO,
            description=f"A GraphQL API endpoint was found at {gql_url}.",
            evidence=f"Endpoint: {gql_url}",
            remediation="Ensure GraphQL endpoint is properly secured with authentication.",
            reference="https://owasp.org/www-project-web-security-testing-guide/",
        ))

        # 2. Introspection enabled (should be disabled in production)
        try:
            resp = client.post(
                gql_url,
                content=INTROSPECTION_QUERY,
                headers={"Content-Type": "application/json"},
            )
            data = resp.json()
            if "data" in data and "__schema" in str(data.get("data", {})):
                schema_types = data.get("data", {}).get("__schema", {}).get("types", [])
                type_names = [t.get("name") for t in schema_types if t.get("name")]

                findings.append(Finding(
                    title="GraphQL Introspection Enabled in Production",
                    severity=Severity.MEDIUM,
                    description=(
                        "GraphQL introspection is enabled, allowing anyone to query the full "
                        "API schema — all types, fields, queries, and mutations. "
                        "Attackers use this to map your entire API and find exploitable operations."
                    ),
                    evidence=(
                        f"Introspection query returned {len(type_names)} types.\n"
                        f"Sample types: {', '.join(type_names[:10])}"
                    ),
                    remediation="Disable introspection in production. Allow only in development.",
                    code_fix=(
                        "# Apollo Server (Node.js):\n"
                        "const server = new ApolloServer({\n"
                        "    introspection: process.env.NODE_ENV !== 'production'\n"
                        "})\n\n"
                        "# Python (Graphene/Strawberry):\n"
                        "# Use a validation rule to disable introspection:\n"
                        "from graphql import NoSchemaIntrospectionCustomRule"
                    ),
                    reference="https://owasp.org/www-project-top-10-api-security-risks/",
                    cvss=5.3,
                ))
        except Exception:
            pass

        # 3. Batch query abuse (DoS potential)
        try:
            resp = client.post(
                gql_url,
                content=BATCH_QUERY,
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code == 200:
                body = resp.json() if resp.text.strip().startswith("[") else None
                if isinstance(body, list) and len(body) >= 2:
                    findings.append(Finding(
                        title="GraphQL Batch Queries Enabled",
                        severity=Severity.MEDIUM,
                        description=(
                            "GraphQL batch queries are enabled, allowing multiple operations "
                            "in a single request. This can be abused to bypass rate limiting "
                            "or perform credential stuffing via batched login mutations."
                        ),
                        evidence=f"Batch query with 3 operations returned HTTP {resp.status_code}",
                        remediation="Disable batch queries or implement per-query rate limiting.",
                        code_fix=(
                            "# Apollo Server — disable batching:\n"
                            "const server = new ApolloServer({ allowBatchedHttpRequests: false })"
                        ),
                        reference="https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
                    ))
        except Exception:
            pass

        # 4. Deeply nested query (DoS via query complexity)
        try:
            resp = client.post(
                gql_url,
                content=DEEP_QUERY,
                headers={"Content-Type": "application/json"},
                timeout=5.0,
            )
            if resp.status_code == 200 and '"data"' in resp.text:
                findings.append(Finding(
                    title="GraphQL No Query Depth Limiting",
                    severity=Severity.MEDIUM,
                    description=(
                        "The GraphQL API accepted a deeply nested query without error. "
                        "Without query depth limits, attackers can craft exponentially "
                        "expensive queries to cause denial of service."
                    ),
                    evidence="Deeply nested introspection query succeeded",
                    remediation="Implement query depth limiting and complexity analysis.",
                    code_fix=(
                        "# graphql-depth-limit (Node.js):\n"
                        "import depthLimit from 'graphql-depth-limit'\n"
                        "const server = new ApolloServer({\n"
                        "    validationRules: [depthLimit(5)]\n"
                        "})\n\n"
                        "# Python (Graphene):\n"
                        "# Use graphene-django-optimizer or add custom depth middleware"
                    ),
                    reference="https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
                ))
        except Exception:
            pass

        # 5. GraphQL over GET (CSRF risk)
        try:
            resp = client.get(
                gql_url,
                params={"query": "{ __typename }"},
            )
            if resp.status_code == 200 and "__typename" in resp.text:
                findings.append(Finding(
                    title="GraphQL Accepts GET Requests (CSRF Risk)",
                    severity=Severity.LOW,
                    description=(
                        "The GraphQL endpoint accepts queries via GET requests. "
                        "This enables CSRF attacks where malicious pages can trigger "
                        "mutations using the victim's browser cookies."
                    ),
                    evidence=f"GET {gql_url}?query={{__typename}} → HTTP {resp.status_code}",
                    remediation=(
                        "Only accept GraphQL queries via POST. "
                        "Reject GET requests for mutations."
                    ),
                    code_fix="// Apollo Server: httpMethod: 'POST' only in middleware config",
                    reference="https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
                ))
        except Exception:
            pass

    return findings
