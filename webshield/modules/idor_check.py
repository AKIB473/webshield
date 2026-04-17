"""
IDOR / Broken Access Control Detection Module
Tests for Insecure Direct Object References — the #1 real-world exploited
vulnerability class in 2025 (OWASP A01:2025 - Broken Access Control).

Approach:
- Discovers API endpoints that return objects with numeric/UUID IDs
- Probes adjacent IDs to see if access control is enforced
- Checks for unauthenticated access to user-specific resources
- Tests common IDOR patterns in URL paths and query parameters
"""

from __future__ import annotations
import re
from typing import List, Optional
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

# Common API patterns that are prone to IDOR
IDOR_PROBE_PATHS = [
    # REST resource patterns
    "/api/v1/users/{id}",
    "/api/v1/user/{id}",
    "/api/users/{id}",
    "/api/user/{id}",
    "/api/v1/orders/{id}",
    "/api/v1/order/{id}",
    "/api/orders/{id}",
    "/api/v1/accounts/{id}",
    "/api/v1/account/{id}",
    "/api/v1/profile/{id}",
    "/api/v1/profiles/{id}",
    "/api/v1/invoices/{id}",
    "/api/v1/payments/{id}",
    "/api/v1/tickets/{id}",
    "/api/v1/documents/{id}",
    "/api/v1/files/{id}",
    "/api/v1/reports/{id}",
    # Generic patterns
    "/api/{id}",
    "/user/{id}",
    "/users/{id}",
    "/profile/{id}",
    "/account/{id}",
    "/order/{id}",
    "/invoice/{id}",
]

# Common query param patterns for IDOR
IDOR_QUERY_PARAMS = [
    "id", "user_id", "userId", "account_id", "accountId",
    "order_id", "orderId", "file_id", "fileId",
    "uid", "pid", "cid", "rid",
]

# IDs to probe — start with very common low IDs
PROBE_IDS = [1, 2, 3, 100, 1000]


def _looks_like_user_data(body: str) -> bool:
    """Returns True if the response body looks like it contains user/object data."""
    signals = [
        "email", "username", "user_id", "userid", "first_name", "last_name",
        "phone", "address", "account", "profile", "order", "invoice",
        "password", "token", "api_key", "credit_card", "ssn",
    ]
    body_lower = body.lower()
    return sum(1 for s in signals if s in body_lower) >= 2


def _responses_differ_meaningfully(r1_body: str, r2_body: str) -> bool:
    """
    Returns True if two responses look like different user records
    (both have data, but data differs — suggesting real per-user access).
    """
    if not r1_body or not r2_body:
        return False
    # Both must look like real data
    if not (_looks_like_user_data(r1_body) and _looks_like_user_data(r2_body)):
        return False
    # They should differ (different user records)
    return r1_body.strip() != r2_body.strip()


def _check_path_idor(
    client, base: str, path_template: str, findings: List[Finding]
) -> None:
    """
    Tests a path template like /api/v1/users/{id} with multiple IDs.
    If multiple IDs return 200 with data — IDOR is likely.
    """
    successful_ids = []
    responses = {}

    for probe_id in PROBE_IDS:
        path = path_template.replace("{id}", str(probe_id))
        target = base + path
        try:
            resp = client.get(
                target,
                headers={"Accept": "application/json"},
            )
            if resp.status_code == 200 and len(resp.text.strip()) > 30:
                ct = resp.headers.get("content-type", "")
                # Only flag JSON responses or responses that look like user data
                if "json" in ct or _looks_like_user_data(resp.text):
                    successful_ids.append(probe_id)
                    responses[probe_id] = resp.text
        except Exception:
            continue

    if len(successful_ids) >= 2:
        # Multiple IDs returned data without auth — likely IDOR
        base_path = path_template.replace("/{id}", "")

        # Check if responses are meaningfully different (different user records)
        ids = list(responses.keys())[:2]
        records_differ = _responses_differ_meaningfully(
            responses[ids[0]], responses[ids[1]]
        )

        severity = Severity.HIGH if records_differ else Severity.MEDIUM

        findings.append(Finding(
            title=f"Potential IDOR — Sequential IDs Accessible: {base_path}",
            severity=severity,
            description=(
                f"The API endpoint {base_path}/{{id}} returned data for "
                f"{len(successful_ids)} different IDs ({', '.join(map(str, successful_ids))}) "
                "without requiring authentication. Attackers can enumerate all records "
                "by incrementing the ID — exposing other users' data. "
                "This is the #1 exploited vulnerability class in 2025 (OWASP A01)."
            ),
            evidence=(
                f"Endpoint template: {base + base_path}/{{id}}\n"
                f"IDs that returned HTTP 200 with data: {successful_ids}\n"
                f"Responses contain user data: {records_differ}"
            ),
            remediation=(
                "Enforce authorization on every object access request. "
                "Verify the requesting user owns or has permission to access the requested object. "
                "Never rely on the client to enforce access control. "
                "Use UUIDs instead of sequential integers where possible."
            ),
            code_fix=(
                "# Python / Django — always scope to request.user:\n"
                "# BAD:\n"
                "obj = Order.objects.get(id=request.GET['id'])\n\n"
                "# GOOD:\n"
                "obj = Order.objects.get(id=request.GET['id'], user=request.user)\n"
                "# Raises DoesNotExist if user doesn't own it\n\n"
                "# Node.js / Express:\n"
                "// BAD:\n"
                "const order = await Order.findById(req.params.id);\n\n"
                "// GOOD:\n"
                "const order = await Order.findOne({\n"
                "  _id: req.params.id,\n"
                "  userId: req.user.id  // scoped to current user\n"
                "});\n"
                "if (!order) return res.status(403).json({ error: 'Forbidden' });"
            ),
            reference="https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
            module="idor_check",
            cvss=8.1 if severity == Severity.HIGH else 6.5,
        ))


def _check_query_param_idor(
    client, base: str, findings: List[Finding]
) -> None:
    """
    Tests common query parameter IDOR patterns on the root and /api paths.
    e.g. /?user_id=1, /api?id=2
    """
    test_bases = [base + "/", base + "/api/"]
    found_params: List[str] = []

    for test_base in test_bases:
        for param in IDOR_QUERY_PARAMS[:6]:  # limit to top 6 — be fast
            try:
                r1 = client.get(f"{test_base}?{param}=1",
                                headers={"Accept": "application/json"})
                r2 = client.get(f"{test_base}?{param}=2",
                                headers={"Accept": "application/json"})

                if (r1.status_code == 200 and r2.status_code == 200 and
                        len(r1.text.strip()) > 50 and len(r2.text.strip()) > 50):
                    if _looks_like_user_data(r1.text) and r1.text != r2.text:
                        found_params.append(f"{test_base}?{param}=N")
            except Exception:
                continue

    if found_params:
        findings.append(Finding(
            title="Potential IDOR via Query Parameters",
            severity=Severity.HIGH,
            description=(
                "Query parameter ID manipulation returns different user/object data "
                "without authentication. Attackers can enumerate all records by "
                "changing the ID value in the URL."
            ),
            evidence=f"Vulnerable parameter patterns: {', '.join(found_params[:3])}",
            remediation=(
                "Never trust client-supplied IDs for access control. "
                "Always verify the authenticated user owns the requested object server-side."
            ),
            code_fix=(
                "# Always scope database queries to the authenticated user:\n"
                "user_data = db.query(User).filter(\n"
                "    User.id == requested_id,\n"
                "    User.owner_id == current_user.id  # <-- critical check\n"
                ").first()\n"
                "if not user_data:\n"
                "    raise HTTPException(status_code=403, detail='Forbidden')"
            ),
            reference="https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
            module="idor_check",
            cvss=7.5,
        ))


def _check_unauthenticated_user_endpoint(
    client, base: str, findings: List[Finding]
) -> None:
    """Check if /api/v1/users or similar endpoints list all users without auth."""
    list_endpoints = [
        "/api/v1/users", "/api/users", "/api/v1/accounts",
        "/api/v1/members", "/api/members", "/api/v1/profiles",
    ]
    for path in list_endpoints:
        try:
            resp = client.get(
                base + path,
                headers={"Accept": "application/json"},
            )
            if resp.status_code != 200:
                continue
            body = resp.text
            if len(body.strip()) < 50:
                continue
            ct = resp.headers.get("content-type", "")
            if "json" not in ct and not _looks_like_user_data(body):
                continue

            # Check if it looks like a list of users
            body_lower = body.lower()
            user_list_signals = sum(1 for kw in
                                    ["email", "username", "user_id", "name", "phone"]
                                    if kw in body_lower)
            # Check for array/list structure
            is_list = body.strip().startswith("[") or '"results"' in body_lower or '"users"' in body_lower

            if user_list_signals >= 2 or is_list:
                has_sensitive = any(kw in body_lower for kw in
                                    ["password", "secret", "token", "api_key", "ssn", "credit"])
                severity = Severity.CRITICAL if has_sensitive else Severity.HIGH

                findings.append(Finding(
                    title=f"User List Accessible Without Authentication: {path}",
                    severity=severity,
                    description=(
                        f"The endpoint {path} returns a list of user records "
                        "without requiring authentication. Attackers can harvest "
                        "usernames, emails, and other PII for phishing or credential stuffing."
                        + (" Sensitive data (passwords/tokens) may be exposed." if has_sensitive else "")
                    ),
                    evidence=(
                        f"HTTP 200 at {base + path}\n"
                        f"Response contains user data fields\n"
                        f"Sensitive data detected: {has_sensitive}"
                    ),
                    remediation=(
                        "Require authentication on all user listing endpoints. "
                        "Limit what fields are returned (never return passwords/tokens). "
                        "Implement pagination and rate limiting on list endpoints."
                    ),
                    code_fix=(
                        "# FastAPI — require auth:\n"
                        "from fastapi import Depends\n"
                        "from app.auth import get_current_user\n\n"
                        "@router.get('/users')\n"
                        "async def list_users(current_user = Depends(get_current_user)):\n"
                        "    # Only admins should list all users\n"
                        "    if not current_user.is_admin:\n"
                        "        raise HTTPException(status_code=403)\n"
                        "    return users_service.list()"
                    ),
                    reference="https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
                    module="idor_check",
                    cvss=9.1 if severity == Severity.CRITICAL else 7.5,
                ))
                return

        except Exception:
            continue


def scan(url: str, timeout: float = 15.0) -> List[Finding]:
    findings: List[Finding] = []
    base = url.rstrip("/")

    with get_client(timeout=min(timeout, 10.0)) as client:
        # 1. Test common path-based IDOR patterns
        for path_template in IDOR_PROBE_PATHS[:10]:  # top 10 most common
            _check_path_idor(client, base, path_template, findings)
            if len(findings) >= 3:
                break  # avoid flooding — 3 findings is enough signal

        # 2. Test query param IDOR
        if len(findings) < 3:
            _check_query_param_idor(client, base, findings)

        # 3. Check unauthenticated user list endpoints
        _check_unauthenticated_user_endpoint(client, base, findings)

    return findings
