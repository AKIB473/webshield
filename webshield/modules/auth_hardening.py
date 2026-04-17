"""
Authentication Hardening Module
Tests login endpoints for: rate limiting, account lockout, MFA signals,
default credentials, password reset flaws, and auth header security.
OWASP A07:2025 - Authentication Failures | A01:2025 - Broken Access Control
"""

from __future__ import annotations
import time
from typing import List, Optional, Tuple
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

LOGIN_PATHS = [
    "/login", "/signin", "/sign-in", "/auth", "/auth/login",
    "/api/login", "/api/auth", "/api/auth/login", "/api/signin",
    "/api/v1/auth", "/api/v1/login", "/api/v2/auth",
    "/user/login", "/users/login", "/account/login", "/accounts/login",
    "/session", "/sessions", "/auth/session",
    "/wp-login.php", "/admin/login", "/admin/signin",
    "/panel/login", "/dashboard/login",
]

PASSWORD_RESET_PATHS = [
    "/forgot-password", "/forgot_password", "/reset-password",
    "/password/reset", "/password/forgot", "/auth/forgot",
    "/api/auth/forgot-password", "/api/v1/password/reset",
    "/account/forgot-password", "/users/password/new",
]

# Common default credentials to test (clearly invalid — just testing lockout)
DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("administrator", "administrator"),
    ("root", "root"),
    ("test", "test"),
]

CAPTCHA_SIGNALS = [
    "captcha", "recaptcha", "hcaptcha", "turnstile",
    "g-recaptcha", "h-captcha", "cf-turnstile",
]

RATE_LIMIT_SIGNALS = [
    "rate limit", "too many", "too many attempts", "slow down",
    "locked", "account locked", "temporarily locked", "blocked",
    "throttl", "try again later", "wait", "cool", "flood",
]

MFA_SIGNALS = [
    "two-factor", "2fa", "two factor", "totp", "otp",
    "authenticator", "verification code", "multi-factor", "mfa",
    "one-time", "second factor",
]


def _find_login_endpoint(
    client, base: str
) -> Optional[Tuple[str, int]]:
    """Returns (path, status_code) of first accessible login endpoint."""
    for path in LOGIN_PATHS:
        try:
            resp = client.get(base + path)
            if resp.status_code in (200, 302, 405):
                body = resp.text.lower()
                # Must look like a real login page or API endpoint
                if any(kw in body for kw in
                       ["password", "login", "signin", "email", "username",
                        "credential", "log in", "sign in"]):
                    return path, resp.status_code
                # Or it returned JSON (likely API)
                ct = resp.headers.get("content-type", "")
                if "json" in ct:
                    return path, resp.status_code
        except Exception:
            continue
    return None


def _check_rate_limiting(
    client, login_url: str, findings: List[Finding], path: str
) -> bool:
    """
    Send 8 rapid-fire fake login attempts.
    Returns True if rate limiting was detected.
    """
    statuses = []
    blocked = False
    block_trigger = None

    for i in range(8):
        try:
            r = client.post(
                login_url,
                json={"email": f"probe{i}@webshield-test.invalid",
                      "password": "definitely_wrong_password_probe",
                      "username": f"probe{i}",
                      "user": f"probe{i}"},
            )
            statuses.append(r.status_code)

            if r.status_code == 429:
                blocked = True
                block_trigger = f"HTTP 429 received after {i + 1} attempt(s)"
                break

            if r.status_code in (423, 503):
                blocked = True
                block_trigger = f"HTTP {r.status_code} after {i + 1} attempt(s)"
                break

            body_lower = r.text.lower()
            if any(sig in body_lower for sig in RATE_LIMIT_SIGNALS):
                blocked = True
                block_trigger = f"Rate limit message detected after {i + 1} attempt(s)"
                break

            time.sleep(0.2)
        except Exception:
            break

    if blocked:
        findings.append(Finding(
            title=f"Login Rate Limiting Active: {path}",
            severity=Severity.INFO,
            description=f"Rate limiting or lockout detected on login endpoint {path}. Good.",
            evidence=f"{block_trigger}\nStatuses: {statuses}",
            module="auth_hardening",
        ))
        return True

    if len(statuses) >= 5:
        all_same = len(set(statuses)) == 1
        if all_same and statuses[0] in (200, 400, 401, 403, 422):
            findings.append(Finding(
                title=f"No Rate Limiting on Login Endpoint: {path}",
                severity=Severity.HIGH,
                description=(
                    f"The login endpoint at {path} does not enforce rate limiting. "
                    "All 8 consecutive probe requests were accepted without throttling, "
                    "CAPTCHA, or lockout. Attackers can run unlimited brute-force or "
                    "credential stuffing attacks (88% of web breaches per Verizon DBIR 2025)."
                ),
                evidence=(
                    f"Endpoint: {login_url}\n"
                    f"8 probe requests, responses: {statuses}\n"
                    "No HTTP 429, no CAPTCHA, no lockout message detected."
                ),
                remediation=(
                    "Implement rate limiting on all authentication endpoints. "
                    "Lock accounts after 5–10 failed attempts with exponential backoff. "
                    "Add CAPTCHA for repeated failures. Monitor for credential stuffing patterns."
                ),
                code_fix=(
                    "# Python / Flask:\n"
                    "from flask_limiter import Limiter\n"
                    "limiter = Limiter(app, key_func=get_remote_address)\n"
                    "@app.route('/login', methods=['POST'])\n"
                    "@limiter.limit('5 per minute')\n"
                    "def login(): ...\n\n"
                    "# Node.js / Express:\n"
                    "const rateLimit = require('express-rate-limit');\n"
                    "const loginLimiter = rateLimit({\n"
                    "  windowMs: 15 * 60 * 1000,\n"
                    "  max: 10,\n"
                    "  message: 'Too many login attempts'\n"
                    "});\n"
                    "app.post('/login', loginLimiter, loginHandler);\n\n"
                    "# Django:\n"
                    "# pip install django-axes\n"
                    "INSTALLED_APPS += ['axes']\n"
                    "AXES_FAILURE_LIMIT = 5"
                ),
                reference="https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
                module="auth_hardening",
                cvss=7.5,
            ))
    return False


def _check_mfa_signals(
    client, login_url: str, findings: List[Finding], path: str
) -> None:
    """Check if MFA/2FA is mentioned in the login page."""
    try:
        resp = client.get(login_url)
        body_lower = resp.text.lower()
        has_mfa = any(sig in body_lower for sig in MFA_SIGNALS)
        has_captcha = any(sig in body_lower for sig in CAPTCHA_SIGNALS)

        if has_mfa:
            findings.append(Finding(
                title=f"MFA/2FA Detected on Login: {path}",
                severity=Severity.INFO,
                description=f"Multi-factor authentication signals detected on {path}. Good security practice.",
                evidence=f"MFA keywords found in login page at {login_url}",
                module="auth_hardening",
            ))
        else:
            findings.append(Finding(
                title=f"No MFA/2FA Detected on Login: {path}",
                severity=Severity.MEDIUM,
                description=(
                    f"No multi-factor authentication signals found on the login page at {path}. "
                    "Applications without MFA are significantly more vulnerable to "
                    "credential stuffing and phishing attacks."
                ),
                evidence=f"No 2FA/TOTP/OTP keywords found at {login_url}",
                remediation=(
                    "Implement multi-factor authentication (MFA) for all user accounts, "
                    "especially admin accounts. Use TOTP (Google Authenticator), "
                    "WebAuthn/passkeys, or SMS OTP as a minimum."
                ),
                code_fix=(
                    "# Python — django-otp:\n"
                    "# pip install django-otp\n"
                    "INSTALLED_APPS += ['django_otp', 'django_otp.plugins.otp_totp']\n\n"
                    "# Node.js — speakeasy:\n"
                    "const speakeasy = require('speakeasy');\n"
                    "const token = speakeasy.totp({ secret: user.mfa_secret, encoding: 'base32' });\n\n"
                    "# Or use passkeys (WebAuthn) for phishing-resistant auth:\n"
                    "# https://webauthn.guide"
                ),
                reference="https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html",
                module="auth_hardening",
                cvss=5.9,
            ))

        if has_captcha:
            findings.append(Finding(
                title=f"CAPTCHA Detected on Login: {path}",
                severity=Severity.INFO,
                description=f"CAPTCHA protection detected on login page at {path}.",
                evidence=f"CAPTCHA keywords found at {login_url}",
                module="auth_hardening",
            ))
    except Exception:
        pass


def _check_default_credentials(
    client, login_url: str, findings: List[Finding], path: str
) -> None:
    """Test a small set of default credentials."""
    for username, password in DEFAULT_CREDENTIALS[:3]:  # limit to 3 — be polite
        try:
            r = client.post(
                login_url,
                json={"username": username, "password": password,
                      "email": username, "user": username},
            )
            body_lower = r.text.lower()
            ct = r.headers.get("content-type", "")

            # Success signals
            success = (
                r.status_code in (200, 302) and
                any(kw in body_lower for kw in
                    ["dashboard", "welcome", "token", "access_token",
                     "logout", "profile", "account"]) and
                not any(kw in body_lower for kw in
                        ["invalid", "incorrect", "failed", "error",
                         "wrong", "unauthorized", "denied"])
            )

            # JWT token in response is a strong success signal
            if "application/json" in ct:
                import json as _json
                try:
                    data = _json.loads(r.text)
                    if any(k in data for k in ["token", "access_token", "jwt", "session"]):
                        success = True
                except Exception:
                    pass

            if success:
                findings.append(Finding(
                    title=f"Default Credentials Accepted: {username}/{password}",
                    severity=Severity.CRITICAL,
                    description=(
                        f"The application accepted default credentials ({username}/{password}) "
                        f"on login endpoint {path}. An attacker has full access to this account."
                    ),
                    evidence=(
                        f"POST {login_url} with {username}:{password}\n"
                        f"HTTP {r.status_code} — response suggests successful login"
                    ),
                    remediation=(
                        "Immediately change all default credentials. "
                        "Force password reset on first login. "
                        "Audit all accounts for weak/default passwords."
                    ),
                    code_fix=(
                        "# Force password change on first login:\n"
                        "if user.is_default_password:\n"
                        "    return redirect('/change-password')\n\n"
                        "# Django — use password validators:\n"
                        "AUTH_PASSWORD_VALIDATORS = [\n"
                        "    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',\n"
                        "     'OPTIONS': {'min_length': 12}},\n"
                        "    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},\n"
                        "]"
                    ),
                    reference="https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication",
                    module="auth_hardening",
                    cvss=9.8,
                ))
                return  # one critical finding is enough

            time.sleep(0.3)
        except Exception:
            continue


def _check_password_reset(
    client, base: str, findings: List[Finding]
) -> None:
    """Check password reset endpoint for security issues."""
    for path in PASSWORD_RESET_PATHS:
        try:
            resp = client.get(base + path)
            if resp.status_code not in (200, 405):
                continue

            body_lower = resp.text.lower()
            if not any(kw in body_lower for kw in
                       ["password", "reset", "forgot", "email", "recovery"]):
                continue

            # Check if reset uses security questions (weak)
            uses_security_questions = any(kw in body_lower for kw in
                                          ["security question", "mother's maiden",
                                           "pet name", "first school"])
            if uses_security_questions:
                findings.append(Finding(
                    title=f"Weak Password Reset — Security Questions Used: {path}",
                    severity=Severity.MEDIUM,
                    description=(
                        f"Password reset at {path} uses security questions, "
                        "which are considered weak and guessable. "
                        "Attackers can often bypass these through social engineering or OSINT."
                    ),
                    evidence=f"Security question keywords found at {base + path}",
                    remediation=(
                        "Replace security questions with email-based OTP tokens or magic links. "
                        "Token should expire in 15 minutes and be single-use."
                    ),
                    code_fix=(
                        "# Secure password reset flow:\n"
                        "import secrets, hashlib\n"
                        "token = secrets.token_urlsafe(32)  # Cryptographically secure\n"
                        "hashed = hashlib.sha256(token.encode()).hexdigest()\n"
                        "# Store hashed token with expiry (15 min)\n"
                        "# Send plain token via email\n"
                        "# On reset: hash submitted token and compare to stored hash"
                    ),
                    reference="https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html",
                    module="auth_hardening",
                    cvss=5.3,
                ))

            findings.append(Finding(
                title=f"Password Reset Endpoint Found: {path}",
                severity=Severity.INFO,
                description=(
                    f"Password reset functionality found at {path}. "
                    "Ensure tokens are cryptographically random, single-use, "
                    "and expire within 15 minutes."
                ),
                evidence=f"HTTP {resp.status_code} at {base + path}",
                remediation=(
                    "Verify reset tokens: cryptographically random (min 32 bytes), "
                    "single-use, 15-minute expiry, sent only to verified email."
                ),
                reference="https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html",
                module="auth_hardening",
            ))
            return  # found one, that's enough

        except Exception:
            continue


def scan(url: str, timeout: float = 15.0) -> List[Finding]:
    findings: List[Finding] = []
    base = url.rstrip("/")

    with get_client(timeout=min(timeout, 10.0)) as client:
        # 1. Find a login endpoint
        result = _find_login_endpoint(client, base)
        if not result:
            return findings

        path, _ = result
        login_url = base + path

        # 2. Test rate limiting
        _check_rate_limiting(client, login_url, findings, path)

        # 3. Check MFA signals
        _check_mfa_signals(client, login_url, findings, path)

        # 4. Test default credentials (only if no rate limiting found — avoid lockout)
        rate_limited = any(
            "rate limiting active" in f.title.lower() for f in findings
        )
        if not rate_limited:
            _check_default_credentials(client, login_url, findings, path)

        # 5. Check password reset
        _check_password_reset(client, base, findings)

    return findings
