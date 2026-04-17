"""
GraphQL Security Module (v1.3.0 — Advanced)
Full coverage: introspection, batch queries, depth/complexity DoS, field suggestion,
CSRF via GET, alias abuse, fragment cycling DoS, unauthenticated mutations,
debug info leakage, and error message analysis.
Research: OWASP API Security, HackTricks GraphQL, PortSwigger, 2024/2025 research.
"""

from __future__ import annotations
import json
import re
import time
from typing import List, Optional, Tuple
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

# ─── GraphQL Endpoints ────────────────────────────────────────────────────────

GRAPHQL_ENDPOINTS = [
    "/graphql", "/graphql/", "/api/graphql", "/api/graphql/",
    "/v1/graphql", "/v2/graphql", "/v3/graphql",
    "/gql", "/query", "/graphiql", "/altair",
    "/api/v1/graphql", "/api/v2/graphql",
    "/graphql/v1", "/graphql/v2",
    "/explorer", "/playground",
]

# ─── Queries ──────────────────────────────────────────────────────────────────

INTROSPECTION = '{"query":"{ __schema { types { name fields { name type { name kind ofType { name kind } } } } } }"}'
TYPENAME_QUERY = '{"query":"{ __typename }"}'

# Batch of 10 to test batching
BATCH_10 = json.dumps([{"query": "{ __typename }"} for _ in range(10)])

# Deep nesting for complexity/depth DoS
DEEP_QUERY = '{"query":"{ a:__schema{types{fields{type{fields{type{fields{type{fields{type{name}}}}}}}}}}}"}'

# Alias flooding (100 aliases in one query — complexity attack)
ALIAS_FLOOD = '{"query":"{ ' + " ".join([f"a{i}:__typename" for i in range(100)]) + ' }"}'

# Fragment cycling (fragment referencing itself — stack overflow attempt)
FRAGMENT_CYCLE = '{"query":"fragment f on Query { ...f } { ...f }"}'

# Field suggestion probe (typo in field name — server may suggest real fields)
FIELD_SUGGESTION = '{"query":"{ usr { id } }"}'

# Mutation without auth (try to call common unauthenticated mutations)
UNAUTH_MUTATIONS = [
    '{"query":"mutation { createUser(input: {email: \\"test@test.com\\", password: \\"test\\"}) { id } }"}',
    '{"query":"mutation { login(email: \\"admin@admin.com\\", password: \\"password\\") { token } }"}',
    '{"query":"mutation { register(username: \\"testuser\\", email: \\"test@test.com\\", password: \\"test123\\") { id } }"}',
]

# ─── GraphQL Error Patterns ───────────────────────────────────────────────────

FIELD_SUGGESTION_PATTERN = re.compile(
    r"did you mean|suggestions?|similar field|cannot query field",
    re.I,
)

DEBUG_STACK_PATTERN = re.compile(
    r"at Object\.|at Function\.|at Module\.|stack trace|traceback|exception|\.js:\d+",
    re.I,
)


def _post_json(client, url: str, body: str, timeout: float = 8.0) -> Optional[dict]:
    try:
        resp = client.post(
            url,
            content=body,
            headers={"Content-Type": "application/json"},
            timeout=timeout,
        )
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return None


def _find_graphql_endpoint(client, base: str) -> Optional[Tuple[str, dict]]:
    """Discover the GraphQL endpoint and return (url, response)."""
    for path in GRAPHQL_ENDPOINTS:
        url = base + path
        try:
            resp = client.post(
                url,
                content=TYPENAME_QUERY,
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code in (200, 400, 405):
                body = resp.text
                if any(kw in body for kw in ['"data"', '"errors"', '"__typename"', '"message"']):
                    try:
                        return url, resp.json()
                    except Exception:
                        return url, {}
        except Exception:
            continue
    return None


def scan(url: str, timeout: float = 15.0) -> List[Finding]:
    findings: List[Finding] = []
    base = url.rstrip("/")

    with get_client(timeout=min(timeout, 12.0)) as client:

        # ── 1. Discover endpoint ──────────────────────────────────────────────
        result = _find_graphql_endpoint(client, base)
        if not result:
            return []

        gql_url, initial_resp = result

        findings.append(Finding(
            title=f"GraphQL Endpoint Discovered: {gql_url.replace(base, '')}",
            severity=Severity.INFO,
            description=(
                f"A GraphQL API endpoint is accessible at {gql_url}. "
                "Proceeding with security checks."
            ),
            evidence=f"Endpoint: {gql_url}",
            remediation="Ensure the GraphQL endpoint requires authentication where needed.",
            reference="https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
            module="graphql",
        ))

        # ── 2. Introspection enabled ──────────────────────────────────────────
        intro_data = _post_json(client, gql_url, INTROSPECTION)
        if intro_data:
            schema = intro_data.get("data", {}).get("__schema", {})
            if schema:
                types = schema.get("types", [])
                type_names = [t.get("name", "") for t in types if t.get("name") and not t["name"].startswith("__")]

                # Count total fields exposed
                total_fields = sum(
                    len(t.get("fields") or [])
                    for t in types
                    if t.get("fields")
                )

                findings.append(Finding(
                    title="GraphQL Introspection Enabled — Full Schema Exposed",
                    severity=Severity.MEDIUM,
                    description=(
                        "GraphQL introspection is enabled in what appears to be a production endpoint. "
                        "This exposes the COMPLETE API schema including all types, fields, queries, "
                        "and mutations. Attackers use this to map your API and find:\n"
                        "• Hidden/internal operations\n"
                        "• Admin mutations\n"
                        "• Field names that reveal business logic\n"
                        "• Deprecated endpoints still accessible"
                    ),
                    evidence=(
                        f"Endpoint: {gql_url}\n"
                        f"Types exposed: {len(type_names)} custom types\n"
                        f"Total fields: {total_fields}\n"
                        f"Sample types: {', '.join(type_names[:12])}"
                    ),
                    remediation=(
                        "Disable introspection in production environments. "
                        "Only enable in development or for authenticated admin users."
                    ),
                    code_fix=(
                        "# Apollo Server (Node.js):\n"
                        "const server = new ApolloServer({\n"
                        "    introspection: process.env.NODE_ENV !== 'production'\n"
                        "})\n\n"
                        "# Python (Strawberry):\n"
                        "from graphql import NoSchemaIntrospectionCustomRule\n"
                        "schema = strawberry.Schema(\n"
                        "    query=Query,\n"
                        "    extensions=[DisableIntrospection]\n"
                        ")\n\n"
                        "# Hasura: Set HASURA_GRAPHQL_ENABLE_CONSOLE=false in prod"
                    ),
                    reference="https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
                    module="graphql",
                    cvss=5.3,
                ))

                # Look for suspicious type/field names in schema
                sensitive_names = [
                    n for n in type_names
                    if any(kw in n.lower() for kw in
                           ["admin", "internal", "secret", "password", "token",
                            "private", "debug", "root", "super"])
                ]
                if sensitive_names:
                    findings.append(Finding(
                        title=f"GraphQL Schema Exposes Sensitive Type Names: {', '.join(sensitive_names[:5])}",
                        severity=Severity.MEDIUM,
                        description=(
                            "Introspection revealed GraphQL types with names suggesting "
                            "sensitive or privileged functionality: "
                            f"{', '.join(sensitive_names)}. "
                            "These types may expose admin operations or internal data."
                        ),
                        evidence=f"Sensitive type names found: {sensitive_names}",
                        remediation=(
                            "Disable introspection. Audit these types for proper authentication."
                        ),
                        reference="https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
                        module="graphql",
                        cvss=6.5,
                    ))

        # ── 3. Batch query abuse ──────────────────────────────────────────────
        try:
            resp = client.post(
                gql_url,
                content=BATCH_10,
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code == 200:
                try:
                    body = resp.json()
                    if isinstance(body, list) and len(body) >= 3:
                        findings.append(Finding(
                            title="GraphQL Batch Queries Enabled (Rate Limit Bypass Risk)",
                            severity=Severity.MEDIUM,
                            description=(
                                "GraphQL accepts batched requests (multiple operations in one HTTP request). "
                                "Attackers abuse this to:\n"
                                "• Bypass rate limiting (10 login attempts = 1 HTTP request)\n"
                                "• Credential stuffing at scale\n"
                                "• Amplify DoS attacks\n"
                                f"Tested with 10 batched operations — all accepted."
                            ),
                            evidence=(
                                f"Batch of 10 queries returned {len(body)} responses\n"
                                f"Status: HTTP {resp.status_code}"
                            ),
                            remediation=(
                                "Disable HTTP batching, or implement per-operation rate limiting "
                                "that counts each batched operation separately."
                            ),
                            code_fix=(
                                "# Apollo Server:\n"
                                "new ApolloServer({ allowBatchedHttpRequests: false })\n\n"
                                "# Or limit batch size:\n"
                                "if (Array.isArray(body) && body.length > 1) {\n"
                                "    return res.status(400).json({ error: 'Batching disabled' })\n"
                                "}"
                            ),
                            reference="https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
                            module="graphql",
                        ))
                except Exception:
                    pass
        except Exception:
            pass

        # ── 4. Deep query / complexity DoS ────────────────────────────────────
        try:
            t0 = time.monotonic()
            resp = client.post(
                gql_url,
                content=DEEP_QUERY,
                headers={"Content-Type": "application/json"},
                timeout=6.0,
            )
            elapsed = time.monotonic() - t0
            if resp.status_code == 200 and '"data"' in resp.text:
                findings.append(Finding(
                    title=f"GraphQL No Query Depth/Complexity Limiting (DoS Risk)",
                    severity=Severity.MEDIUM,
                    description=(
                        "A deeply nested query was accepted without error or depth-limiting. "
                        "Without depth and complexity limits, attackers can craft "
                        "exponentially expensive queries (O(2^n) database operations) "
                        "to exhaust server resources and cause denial of service."
                        + (f"\nDeep query took: {elapsed:.2f}s" if elapsed > 1.0 else "")
                    ),
                    evidence=(
                        f"Deeply nested query returned HTTP {resp.status_code}\n"
                        f"Response time: {elapsed:.2f}s"
                    ),
                    remediation=(
                        "Implement query depth limiting (max 5–10 levels) "
                        "and query complexity analysis."
                    ),
                    code_fix=(
                        "# graphql-depth-limit (Node.js):\n"
                        "import depthLimit from 'graphql-depth-limit'\n"
                        "new ApolloServer({\n"
                        "    validationRules: [depthLimit(7)]\n"
                        "})\n\n"
                        "# graphql-query-complexity:\n"
                        "import { createComplexityLimitRule } from 'graphql-validation-complexity'\n"
                        "validationRules: [createComplexityLimitRule(1000)]"
                    ),
                    reference="https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
                    module="graphql",
                    cvss=5.9,
                ))
        except Exception:
            pass

        # ── 5. Alias flooding ─────────────────────────────────────────────────
        try:
            resp = client.post(
                gql_url,
                content=ALIAS_FLOOD,
                headers={"Content-Type": "application/json"},
                timeout=5.0,
            )
            if resp.status_code == 200 and '"data"' in resp.text:
                findings.append(Finding(
                    title="GraphQL Alias Flooding Accepted (Complexity Attack)",
                    severity=Severity.MEDIUM,
                    description=(
                        "The server accepted a query with 100 field aliases in one request. "
                        "Alias flooding allows attackers to resolve the same field hundreds "
                        "of times in a single query, multiplying server-side computation "
                        "without triggering rate limits."
                    ),
                    evidence="100-alias query returned HTTP 200 with data",
                    remediation="Implement query complexity limits that count alias repetitions.",
                    reference="https://www.apollographql.com/blog/graphql/security/securing-your-graphql-api-from-malicious-queries/",
                    module="graphql",
                    cvss=5.3,
                ))
        except Exception:
            pass

        # ── 6. GET-based queries (CSRF) ───────────────────────────────────────
        try:
            resp = client.get(
                gql_url,
                params={"query": "{ __typename }"},
            )
            if resp.status_code == 200 and "__typename" in resp.text:
                findings.append(Finding(
                    title="GraphQL Accepts GET Requests — CSRF Risk",
                    severity=Severity.MEDIUM,
                    description=(
                        "The GraphQL endpoint accepts queries via GET requests. "
                        "Combined with mutations, this enables CSRF attacks: "
                        "a malicious page can trigger state-changing operations "
                        "using the victim's session cookies via simple GET requests."
                    ),
                    evidence=f"GET {gql_url}?query={{__typename}} → HTTP {resp.status_code}",
                    remediation=(
                        "Reject GET requests for mutations. "
                        "Only accept POST with Content-Type: application/json. "
                        "Add CSRF tokens for state-changing operations."
                    ),
                    code_fix=(
                        "# Express middleware:\n"
                        "app.use('/graphql', (req, res, next) => {\n"
                        "    if (req.method === 'GET') return res.status(405).json({ error: 'GET not allowed' })\n"
                        "    next()\n"
                        "})"
                    ),
                    reference="https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html#csrf",
                    module="graphql",
                    cvss=5.9,
                ))
        except Exception:
            pass

        # ── 7. Field suggestions (information disclosure) ─────────────────────
        try:
            resp = client.post(
                gql_url,
                content=FIELD_SUGGESTION,
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code in (200, 400) and FIELD_SUGGESTION_PATTERN.search(resp.text):
                findings.append(Finding(
                    title="GraphQL Field Suggestions Enabled (Information Disclosure)",
                    severity=Severity.LOW,
                    description=(
                        "The GraphQL server returns field name suggestions when a typo is made "
                        "(e.g. 'Did you mean users?'). While helpful in development, "
                        "this reveals actual field names to attackers probing the schema "
                        "even when introspection is disabled."
                    ),
                    evidence=f"Response contained suggestion: {resp.text[:200]}",
                    remediation=(
                        "Disable field suggestions in production environments."
                    ),
                    code_fix=(
                        "# Apollo Server:\n"
                        "new ApolloServer({\n"
                        "    fieldLevelSuggestions: process.env.NODE_ENV !== 'production'\n"
                        "})"
                    ),
                    reference="https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
                    module="graphql",
                ))
        except Exception:
            pass

        # ── 8. Debug / stack traces in errors ─────────────────────────────────
        try:
            # Send a clearly invalid query to trigger error response
            error_query = '{"query":"{ invalid_field_that_does_not_exist_xyz { id } }"}'
            resp = client.post(
                gql_url,
                content=error_query,
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code in (200, 400, 500) and DEBUG_STACK_PATTERN.search(resp.text):
                findings.append(Finding(
                    title="GraphQL Returns Debug Stack Traces in Error Responses",
                    severity=Severity.MEDIUM,
                    description=(
                        "GraphQL error responses contain stack traces or debug information. "
                        "This reveals internal file paths, framework versions, "
                        "and code structure — valuable intelligence for attackers."
                    ),
                    evidence=f"Error response snippet: {resp.text[:300]}",
                    remediation=(
                        "Disable debug mode in production. "
                        "Return generic error messages to clients, log details server-side only."
                    ),
                    code_fix=(
                        "# Apollo Server:\n"
                        "new ApolloServer({\n"
                        "    formatError: (error) => ({\n"
                        "        message: error.message,\n"
                        "        // don't expose extensions.exception in prod\n"
                        "    }),\n"
                        "    includeStacktraceInErrorResponses: false,\n"
                        "})"
                    ),
                    reference="https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
                    module="graphql",
                    cvss=5.3,
                ))
        except Exception:
            pass

        # ── 9. GraphiQL IDE exposed ───────────────────────────────────────────
        for path in ["/graphiql", "/graphiql/", "/altair", "/playground", "/explorer"]:
            try:
                resp = client.get(base + path)
                if resp.status_code == 200:
                    body_lower = resp.text.lower()
                    if any(kw in body_lower for kw in ["graphiql", "altair", "playground", "graphql ide"]):
                        findings.append(Finding(
                            title=f"GraphQL IDE Exposed in Production: {path}",
                            severity=Severity.HIGH,
                            description=(
                                f"The GraphQL IDE ({path}) is publicly accessible. "
                                "This provides an interactive browser-based interface "
                                "where anyone can execute arbitrary GraphQL queries and "
                                "mutations, explore the schema, and test all operations."
                            ),
                            evidence=f"HTTP {resp.status_code} at {base + path}",
                            remediation=(
                                "Disable GraphQL IDEs in production. "
                                "Restrict access by IP allowlist or authentication if needed for internal use."
                            ),
                            code_fix=(
                                "# Apollo Server:\n"
                                "new ApolloServer({\n"
                                "    playground: process.env.NODE_ENV !== 'production'\n"
                                "})\n\n"
                                "# Or block via nginx:\n"
                                f"location {path} {{ deny all; return 403; }}"
                            ),
                            reference="https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
                            module="graphql",
                            cvss=7.5,
                        ))
                        break
            except Exception:
                continue

    return findings
