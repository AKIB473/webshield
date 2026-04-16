"""
JWT Token Analysis Module — UNIQUE, nobody else has this cleanly
Checks for alg:none, weak secrets, missing expiry, sensitive data in payload.
"""

from __future__ import annotations
import re
import json
import base64
from typing import List, Optional
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

WEAK_SECRETS = [
    "secret", "password", "123456", "qwerty", "admin",
    "test", "dev", "changeme", "supersecret", "mysecret",
    "key", "private", "jwt_secret", "app_secret", "",
]

JWT_PATTERN = re.compile(
    r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*'
)


def _b64_decode(s: str) -> Optional[dict]:
    try:
        padded = s + "=" * (4 - len(s) % 4)
        decoded = base64.urlsafe_b64decode(padded)
        return json.loads(decoded)
    except Exception:
        return None


def _check_alg_none(header: dict) -> bool:
    alg = header.get("alg", "").lower()
    return alg in ("none", "")


def _check_weak_secret(token: str) -> Optional[str]:
    """Try known weak secrets (HS256 HMAC brute force)."""
    try:
        import hmac
        import hashlib
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header = _b64_decode(parts[0])
        if not header or header.get("alg", "").upper() not in ("HS256", "HS384", "HS512"):
            return None

        signing_input = f"{parts[0]}.{parts[1]}".encode()
        expected_sig_raw = parts[2]
        padded = expected_sig_raw + "=" * (4 - len(expected_sig_raw) % 4)
        expected_sig = base64.urlsafe_b64decode(padded)

        algo_map = {
            "HS256": hashlib.sha256,
            "HS384": hashlib.sha384,
            "HS512": hashlib.sha512,
        }
        hash_func = algo_map.get(header.get("alg", "").upper(), hashlib.sha256)

        for secret in WEAK_SECRETS:
            computed = hmac.new(secret.encode(), signing_input, hash_func).digest()  # type: ignore[attr-defined]
            if computed == expected_sig:
                return secret
    except Exception:
        pass
    return None


def _analyze_jwt(token: str) -> List[Finding]:
    findings: List[Finding] = []
    parts = token.split(".")
    if len(parts) != 3:
        return []

    header  = _b64_decode(parts[0])
    payload = _b64_decode(parts[1])
    if not header or not payload:
        return []

    # 1. alg:none attack
    if _check_alg_none(header):
        findings.append(Finding(
            title="JWT Uses Algorithm 'none' — Signature Bypass",
            severity=Severity.CRITICAL,
            description=(
                "The JWT token uses alg:none, meaning the signature is not verified. "
                "An attacker can forge any JWT token, change any claims (user_id, role, is_admin), "
                "and the server will accept it without question."
            ),
            evidence=f"JWT header: {json.dumps(header)}",
            remediation="Never accept JWTs with alg:none. Explicitly whitelist allowed algorithms.",
            code_fix=(
                "# Python (PyJWT):\n"
                "jwt.decode(token, key, algorithms=['HS256'])  # never use 'none'\n\n"
                "# Node.js (jsonwebtoken):\n"
                "jwt.verify(token, secret, { algorithms: ['HS256'] })"
            ),
            reference="https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-unverified-signature",
            cvss=9.8,
        ))

    # 2. Weak secret
    weak_secret = _check_weak_secret(token)
    if weak_secret is not None:
        display = f"'{weak_secret}'" if weak_secret else "(empty string)"
        findings.append(Finding(
            title="JWT Signed with Weak Secret",
            severity=Severity.CRITICAL,
            description=(
                f"The JWT secret key is {display}, which is trivially guessable. "
                "Attackers can forge tokens to impersonate any user or escalate privileges."
            ),
            evidence=f"Secret cracked: {display}",
            remediation="Use a cryptographically random secret of at least 256 bits.",
            code_fix=(
                "import secrets\n"
                "JWT_SECRET = secrets.token_hex(32)  # 256-bit random secret\n\n"
                "# Store in environment variable, never in source code:\n"
                "JWT_SECRET = os.environ['JWT_SECRET']"
            ),
            reference="https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-weak-signing-key",
            cvss=9.8,
        ))

    # 3. No expiry (exp claim)
    if "exp" not in payload:
        findings.append(Finding(
            title="JWT Token Has No Expiry (Missing 'exp' Claim)",
            severity=Severity.MEDIUM,
            description=(
                "The JWT token has no 'exp' (expiration) claim. "
                "If a token is stolen, it remains valid forever and cannot be invalidated."
            ),
            evidence=f"JWT payload claims: {list(payload.keys())}",
            remediation="Always set a short expiry on JWT tokens (15–60 minutes for access tokens).",
            code_fix=(
                "import datetime\n"
                "payload = {\n"
                "    'user_id': user.id,\n"
                "    'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)\n"
                "}"
            ),
            reference="https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
        ))

    # 4. Sensitive data in payload
    sensitive_keywords = ["password", "passwd", "secret", "api_key", "credit_card", "ssn", "cvv"]
    payload_str = json.dumps(payload).lower()
    for keyword in sensitive_keywords:
        if keyword in payload_str:
            findings.append(Finding(
                title=f"Sensitive Data in JWT Payload: '{keyword}'",
                severity=Severity.HIGH,
                description=(
                    f"The JWT payload contains '{keyword}'. JWT payloads are Base64-encoded, "
                    "NOT encrypted — anyone can decode and read the payload. "
                    "Sensitive data should never be stored in JWT claims."
                ),
                evidence=f"Found '{keyword}' in decoded JWT payload",
                remediation=(
                    "Remove sensitive data from JWT payload. "
                    "Only store non-sensitive identifiers (user_id, role). "
                    "If encryption is needed, use JWE (JSON Web Encryption)."
                ),
                reference="https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
                cvss=7.5,
            ))
            break

    # 5. Weak algorithm
    alg = header.get("alg", "").upper()
    if alg in ("HS256",):
        findings.append(Finding(
            title="JWT Uses HS256 — Consider Upgrading to RS256",
            severity=Severity.INFO,
            description=(
                "HS256 uses a shared secret for signing. If you have multiple services, "
                "they all share the same secret, meaning any service can forge tokens. "
                "RS256 (asymmetric) is more secure for distributed systems."
            ),
            evidence=f"JWT algorithm: {alg}",
            remediation="For multi-service architectures, prefer RS256 or ES256.",
            reference="https://auth0.com/blog/navigating-rs256-and-hs256/",
        ))

    return findings


def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []

    try:
        with get_client(timeout=timeout) as client:
            resp = client.get(url)
    except Exception:
        return []

    # Hunt for JWTs in cookies, headers, and response body
    search_targets = [
        str(dict(resp.headers)),
        str({k: v for k, v in resp.cookies.items()}),
        resp.text[:5000],
    ]

    seen_tokens = set()
    for target_str in search_targets:
        for match in JWT_PATTERN.finditer(target_str):
            token = match.group(0)
            if token not in seen_tokens:
                seen_tokens.add(token)
                findings.extend(_analyze_jwt(token))

    return findings
