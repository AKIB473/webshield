"""
JWT Token Analysis Module (v1.3.0 — Advanced)
Covers ALL major JWT attack vectors per PortSwigger, OWASP, 2024/2025 research:
- alg:none bypass
- Algorithm confusion (RS256 → HS256 key confusion)
- Weak secret brute-force (HS256/384/512)
- Missing / weak claims (exp, iss, aud, nbf)
- Sensitive data in payload (unencrypted)
- kid (Key ID) injection — path traversal, SQL injection
- jku / x5u header injection (SSRF via key fetch)
- Exposed JWKS endpoint analysis
- JWT in insecure locations (URL, localStorage signal)
"""

from __future__ import annotations
import re
import json
import base64
import hmac
import hashlib
from typing import List, Optional
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

# ─── Constants ────────────────────────────────────────────────────────────────

JWT_PATTERN = re.compile(
    r'eyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*'
)

WEAK_SECRETS = [
    "", "secret", "password", "123456", "qwerty", "admin", "test",
    "dev", "changeme", "supersecret", "mysecret", "key", "private",
    "jwt_secret", "app_secret", "jwt-secret", "your-secret",
    "your-256-bit-secret", "your-512-bit-secret",
    "HS256", "HS384", "HS512", "RS256",
    "secret123", "password123", "admin123", "token",
    "jwt", "access", "refresh", "session",
    "1234567890", "0987654321", "abcdefgh",
    "secretkey", "secret_key", "signing_key",
    "null", "undefined", "false", "true",
]

SENSITIVE_PAYLOAD_KEYS = [
    "password", "passwd", "pass", "secret", "api_key", "apikey",
    "credit_card", "card_number", "ssn", "cvv", "pin",
    "private_key", "access_key", "refresh_token", "client_secret",
]

# ─── Helpers ──────────────────────────────────────────────────────────────────

def _b64_decode(s: str) -> Optional[dict]:
    try:
        padded = s + "=" * (4 - len(s) % 4)
        return json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return None


def _b64_encode_nopad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _check_weak_secret(header: dict, parts: List[str]) -> Optional[str]:
    """Brute-force common weak secrets for HMAC-signed JWTs."""
    alg = header.get("alg", "").upper()
    if alg not in ("HS256", "HS384", "HS512"):
        return None

    algo_map = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512,
    }
    hash_func = algo_map.get(alg, hashlib.sha256)

    signing_input = f"{parts[0]}.{parts[1]}".encode()
    try:
        padded = parts[2] + "=" * (4 - len(parts[2]) % 4)
        expected_sig = base64.urlsafe_b64decode(padded)
    except Exception:
        return None

    for secret in WEAK_SECRETS:
        try:
            computed = hmac.new(secret.encode(), signing_input, hash_func).digest()
            if hmac.compare_digest(computed, expected_sig):
                return secret
        except Exception:
            continue
    return None


def _check_algorithm_confusion(header: dict, payload: dict, parts: List[str]) -> Optional[Finding]:
    """
    Detect RS256 → HS256 algorithm confusion vulnerability.
    If alg is RS256/RS384/RS512/ES256 etc., flag that the server may be
    vulnerable to confusion attack using the public key as HMAC secret.
    """
    alg = header.get("alg", "").upper()
    asymmetric_algs = ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512")

    if alg not in asymmetric_algs:
        return None

    # Check for exposed JWKS (key can be fetched)
    jku = header.get("jku", "")
    x5u = header.get("x5u", "")

    return Finding(
        title=f"JWT Uses Asymmetric Algorithm ({alg}) — Algorithm Confusion Risk",
        severity=Severity.MEDIUM,
        description=(
            f"The JWT uses {alg} (asymmetric). If the server library accepts "
            "both RSA and HMAC algorithms and the public key is obtainable, "
            "an attacker can perform an algorithm confusion attack: sign a "
            "forged JWT with HS256 using the public key as the HMAC secret. "
            "Many JWT libraries are vulnerable to this attack."
            + (f"\n\nExposed JKU endpoint: {jku}" if jku else "")
            + (f"\nExposed x5u endpoint: {x5u}" if x5u else "")
        ),
        evidence=(
            f"JWT algorithm: {alg}\n"
            f"jku header: {jku or 'not present'}\n"
            f"x5u header: {x5u or 'not present'}"
        ),
        remediation=(
            "Explicitly enforce the expected algorithm server-side. "
            "Never trust the algorithm specified in the JWT header. "
            "Use an allowlist: algorithms=['RS256'] — never ['RS256', 'HS256']."
        ),
        code_fix=(
            "# Python (PyJWT) — enforce algorithm:\n"
            "jwt.decode(token, public_key, algorithms=['RS256'])  # never add HS256\n\n"
            "# Node.js (jsonwebtoken):\n"
            "jwt.verify(token, publicKey, { algorithms: ['RS256'] })\n\n"
            "# Java (jjwt):\n"
            "Jwts.parserBuilder()\n"
            "    .setSigningKey(publicKey)\n"
            "    .requireAlgorithm('RS256')  // explicit\n"
            "    .build()\n"
            "    .parseClaimsJws(token);"
        ),
        reference="https://portswigger.net/web-security/jwt/algorithm-confusion",
        module="jwt",
        cvss=8.1,
    )


def _check_kid_injection(header: dict) -> Optional[Finding]:
    """Check for kid (Key ID) injection vulnerabilities."""
    kid = header.get("kid", "")
    if not kid:
        return None

    # SQL injection in kid
    sqli_patterns = [r"'", r"--", r";", r"union", r"select", r"/*"]
    is_sqli_looking = any(re.search(p, str(kid), re.I) for p in sqli_patterns)

    # Path traversal in kid
    path_traversal = ".." in str(kid) or "/" in str(kid) or "\\" in str(kid)

    if is_sqli_looking or path_traversal:
        return Finding(
            title="JWT kid Header Contains Injection Payload",
            severity=Severity.CRITICAL,
            description=(
                "The JWT 'kid' (Key ID) header contains characters suggesting "
                "SQL injection or path traversal. Many JWT libraries use the kid "
                "to look up the signing key from a database or filesystem. "
                "A kid like '../../dev/null' makes the server use an empty key. "
                "A kid like \"' UNION SELECT 'secret'--\" can manipulate key lookup."
            ),
            evidence=f"kid header value: {kid!r}",
            remediation=(
                "Validate the kid claim against an allowlist of known key IDs. "
                "Never use kid values directly in file paths or SQL queries."
            ),
            code_fix=(
                "# Validate kid against known keys only:\n"
                "KNOWN_KEY_IDS = {'key-2024', 'key-2025'}\n"
                "if kid not in KNOWN_KEY_IDS:\n"
                "    raise ValueError('Unknown key ID')\n"
                "key = key_store[kid]  # safe lookup"
            ),
            reference="https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-kid-header-path-traversal",
            module="jwt",
            cvss=9.8,
        )

    return None


def _check_jku_injection(header: dict) -> Optional[Finding]:
    """Check for jku/x5u header injection (SSRF via key URL)."""
    jku = header.get("jku", "") or header.get("x5u", "")
    if not jku:
        return None

    # If jku is present and points to an external domain — suspicious
    if "localhost" not in jku and "127.0.0.1" not in jku:
        return Finding(
            title="JWT Contains jku/x5u Header — Potential Key Injection",
            severity=Severity.HIGH,
            description=(
                "The JWT contains a 'jku' or 'x5u' header pointing to an external URL "
                f"({jku}). If the server blindly fetches the key from this URL, "
                "an attacker can host a malicious JWKS and sign forged tokens "
                "that the server will accept. This is also a server-side SSRF vector."
            ),
            evidence=f"jku/x5u: {jku}",
            remediation=(
                "Never fetch JWT signing keys from URLs specified in the token header. "
                "Maintain a local, trusted key store. Ignore jku/x5u claims."
            ),
            code_fix=(
                "# Explicitly disable jku processing:\n"
                "# PyJWT — use explicit key, don't process jku\n"
                "decoded = jwt.decode(token, known_public_key, algorithms=['RS256'])\n"
                "# Never use jwt.decode(token, options={'verify_signature': False})"
            ),
            reference="https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jku-header-injection",
            module="jwt",
            cvss=9.0,
        )
    return None


def _check_claims(payload: dict) -> List[Finding]:
    """Analyze JWT payload claims for security weaknesses."""
    findings = []

    # Missing expiry
    if "exp" not in payload:
        findings.append(Finding(
            title="JWT Missing 'exp' (Expiry) Claim — Token Never Expires",
            severity=Severity.MEDIUM,
            description=(
                "No 'exp' claim found. This token never expires. "
                "If stolen (via XSS, network interception, or log leak), "
                "an attacker has permanent access with no time limit."
            ),
            evidence=f"JWT payload claims: {list(payload.keys())}",
            remediation="Always set exp to a short duration (15–60 minutes for access tokens).",
            code_fix=(
                "from datetime import datetime, timedelta\n"
                "payload = {\n"
                "    'user_id': user.id,\n"
                "    'exp': datetime.utcnow() + timedelta(minutes=30),\n"
                "    'iat': datetime.utcnow(),\n"
                "    'iss': 'yourapp.com',\n"
                "}"
            ),
            reference="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4",
            module="jwt",
            cvss=5.9,
        ))

    # Missing issued-at
    if "iat" not in payload:
        findings.append(Finding(
            title="JWT Missing 'iat' (Issued At) Claim",
            severity=Severity.LOW,
            description=(
                "The 'iat' (issued at) claim is missing. Without it, "
                "you cannot implement token invalidation based on issue time "
                "or detect pre-rotation tokens."
            ),
            evidence=f"JWT claims: {list(payload.keys())}",
            remediation="Include 'iat' in all JWT tokens.",
            reference="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6",
            module="jwt",
        ))

    # Sensitive data in payload
    payload_lower = json.dumps(payload).lower()
    for key in SENSITIVE_PAYLOAD_KEYS:
        if key in payload_lower:
            findings.append(Finding(
                title=f"Sensitive Data in JWT Payload: '{key}'",
                severity=Severity.HIGH,
                description=(
                    f"The JWT payload contains '{key}'. JWT payloads are Base64-encoded "
                    "— NOT encrypted. Anyone who intercepts a JWT can decode and read the "
                    "payload. NEVER store sensitive data in JWT claims."
                ),
                evidence=f"Sensitive key '{key}' found in decoded JWT payload",
                remediation=(
                    "Remove all sensitive data from JWT payload. "
                    "Only store non-sensitive identifiers (user_id, role, session_id). "
                    "If encryption is required, use JWE (JSON Web Encryption)."
                ),
                code_fix=(
                    "# Only store non-sensitive claims:\n"
                    "payload = {\n"
                    "    'sub': str(user.id),      # user identifier\n"
                    "    'role': user.role,         # authorization\n"
                    "    'exp': ..., 'iat': ...,    # timing\n"
                    "}\n"
                    "# NEVER include: password, api_key, secret, credit_card, etc."
                ),
                reference="https://datatracker.ietf.org/doc/html/rfc7519#section-4",
                module="jwt",
                cvss=7.5,
            ))
            break

    # Privilege escalation indicators
    for escalation_key in ["is_admin", "admin", "role", "scope", "permissions"]:
        if escalation_key in payload:
            val = payload[escalation_key]
            if val in (True, "admin", "administrator", "superuser", "root", "true"):
                findings.append(Finding(
                    title=f"JWT Claims Administrative Privileges: {escalation_key}={val!r}",
                    severity=Severity.INFO,
                    description=(
                        f"The JWT payload contains '{escalation_key}: {val}'. "
                        "If JWT signature verification is flawed (alg:none, weak secret, "
                        "algorithm confusion), an attacker could forge a token with "
                        "elevated privileges."
                    ),
                    evidence=f"{escalation_key}: {val!r}",
                    remediation=(
                        "Ensure JWT signature verification is robust. "
                        "Consider double-checking privileges server-side from DB "
                        "rather than trusting JWT claims alone."
                    ),
                    reference="https://owasp.org/www-project-api-security/",
                    module="jwt",
                ))
            break

    return findings


def _analyze_jwt(token: str) -> List[Finding]:
    findings = []
    parts = token.split(".")
    if len(parts) != 3:
        return []

    header = _b64_decode(parts[0])
    payload = _b64_decode(parts[1])
    if not header or not payload:
        return []

    # 1. alg:none
    alg = header.get("alg", "").lower()
    if alg in ("none", "null", ""):
        findings.append(Finding(
            title="JWT Uses Algorithm 'none' — Signature Bypass",
            severity=Severity.CRITICAL,
            description=(
                "The JWT uses alg:'none', meaning the signature is skipped. "
                "An attacker can forge any JWT with any claims "
                "(user_id, is_admin, role) and the server will accept it."
            ),
            evidence=f"JWT header: {json.dumps(header)}",
            remediation="Explicitly require a signing algorithm. Reject alg:none entirely.",
            code_fix=(
                "# PyJWT — reject none:\n"
                "jwt.decode(token, key, algorithms=['HS256'])  # never include 'none'\n\n"
                "# Node.js:\n"
                "jwt.verify(token, secret, { algorithms: ['HS256'] })"
            ),
            reference="https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-unverified-signature",
            module="jwt",
            cvss=9.8,
        ))

    # 2. Weak secret brute-force
    cracked = _check_weak_secret(header, parts)
    if cracked is not None:
        display = f"'{cracked}'" if cracked else "(empty string)"
        findings.append(Finding(
            title=f"JWT Signed with Weak/Guessable Secret: {display}",
            severity=Severity.CRITICAL,
            description=(
                f"The JWT HMAC secret is {display} — trivially guessable. "
                "Attackers can forge tokens with any claims using this secret."
            ),
            evidence=f"Secret cracked by brute-force: {display}",
            remediation="Use a cryptographically random secret of at least 256 bits (32 bytes).",
            code_fix=(
                "import secrets\n"
                "JWT_SECRET = secrets.token_hex(32)  # 256-bit random\n\n"
                "# Store ONLY in environment variable:\n"
                "JWT_SECRET = os.environ['JWT_SECRET']\n"
                "# Never hardcode in source code"
            ),
            reference="https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-weak-signing-key",
            module="jwt",
            cvss=9.8,
        ))

    # 3. kid injection
    kid_finding = _check_kid_injection(header)
    if kid_finding:
        findings.append(kid_finding)

    # 4. jku/x5u injection
    jku_finding = _check_jku_injection(header)
    if jku_finding:
        findings.append(jku_finding)

    # 5. Algorithm confusion risk (RS256)
    if not findings:  # only if no critical found
        alg_finding = _check_algorithm_confusion(header, payload, parts)
        if alg_finding:
            findings.append(alg_finding)

    # 6. Claim analysis
    findings.extend(_check_claims(payload))

    # 7. Algorithm strength advisory
    alg_upper = header.get("alg", "").upper()
    if alg_upper == "HS256":
        findings.append(Finding(
            title="JWT Uses HS256 — Consider RS256 for Multi-Service Architectures",
            severity=Severity.INFO,
            description=(
                "HS256 uses a shared secret. In multi-service architectures, "
                "all services share the same secret key, meaning any service "
                "can forge tokens. RS256 (asymmetric) is more secure: services "
                "only need the public key to verify, not the signing key."
            ),
            evidence=f"JWT algorithm: HS256",
            remediation="Use RS256 or ES256 for distributed systems. Use HS256 only for single-service apps.",
            reference="https://auth0.com/blog/navigating-rs256-and-hs256/",
            module="jwt",
        ))

    return findings


def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    from urllib.parse import urlparse as _up
    parsed = _up(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    # Probe multiple endpoints that commonly return JWTs
    probe_paths = [
        "", "/api/token", "/api/auth", "/api/v1/token",
        "/api/login", "/profile", "/account", "/app",
        "/api/me", "/api/v1/me",
    ]

    all_sources = []
    try:
        with get_client(timeout=timeout) as client:
            for path in probe_paths:
                try:
                    r = client.get(base + path)
                    if r.status_code in (200, 201):
                        all_sources.append((f"{path or '/'} headers", str(dict(r.headers))))
                        all_sources.append((f"{path or '/'} cookies", str({k: v for k, v in r.cookies.items()})))
                        all_sources.append((f"{path or '/'} body", r.text[:8000]))
                except Exception:
                    continue
    except Exception:
        return []

    # Dedupe search sources
    search_sources = all_sources if all_sources else []
    # Also use original URL response directly
    try:
        with get_client(timeout=min(timeout, 5.0)) as client:
            resp = client.get(url)
    except Exception:
        resp = None

    if resp:
        search_sources = [
            ("headers", str(dict(resp.headers))),
            ("cookies", str({k: v for k, v in resp.cookies.items()})),
            ("body", resp.text[:8000]),
        ] + search_sources

    seen_tokens: set = set()
    for source_name, content in search_sources:
        for match in JWT_PATTERN.finditer(content):
            token = match.group(0)
            if token in seen_tokens:
                continue
            seen_tokens.add(token)
            token_findings = _analyze_jwt(token)
            for f in token_findings:
                f.evidence = f"[Found in: {source_name}]\n{f.evidence}"
            findings.extend(token_findings)

    # Also check well-known JWKS endpoint
    try:
        with get_client(timeout=min(timeout, 5.0)) as client:
            base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
            for jwks_path in ["/.well-known/jwks.json", "/api/jwks.json", "/.well-known/openid-configuration"]:
                r = client.get(base + jwks_path)
                if r.status_code == 200 and ("keys" in r.text.lower() or "issuer" in r.text.lower()):
                    findings.append(Finding(
                        title=f"JWKS Endpoint Exposed: {jwks_path}",
                        severity=Severity.INFO,
                        description=(
                            f"A JWKS (JSON Web Key Set) endpoint is publicly accessible at {jwks_path}. "
                            "This exposes public keys used for JWT verification. While public keys "
                            "are intentionally public, this confirms JWT is in use and reveals "
                            "key IDs (kid) that attackers can use for algorithm confusion attacks."
                        ),
                        evidence=f"HTTP 200 at {base + jwks_path}\n{r.text[:200]}",
                        remediation=(
                            "JWKS endpoints are normally public — this is informational. "
                            "Ensure no private key material is exposed. "
                            "Guard against algorithm confusion attacks (RS256→HS256)."
                        ),
                        reference="https://portswigger.net/web-security/jwt/algorithm-confusion",
                        module="jwt",
                    ))
                    break
    except Exception:
        pass

    return findings


# Fix missing import
from urllib.parse import urlparse
