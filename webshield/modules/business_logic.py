"""
Business Logic & Application Logic Flaw Detection Module (v1.5.0)
OWASP A06:2025 - Insecure Design | Business logic bugs = #2 most reported bug bounty class

Business logic vulnerabilities are flaws in how an application enforces its own rules.
Unlike injection attacks, these can't be detected by WAFs — they require understanding
the application's intended behavior.

Attack categories:
  1. NEGATIVE PRICE / QUANTITY: Order product with qty=-1 to get a refund
  2. PRICE MANIPULATION: Modify price parameter in checkout
  3. MASS ASSIGNMENT: POST extra fields that the server shouldn't accept
     (e.g., {"role":"admin"} in a user update endpoint)
  4. WORKFLOW BYPASS: Skip steps in multi-step processes
     (payment → skip payment step → order complete)
  5. PRIVILEGE ESCALATION: Change user_id/account_id in API requests
  6. RACE CONDITIONS: Double-submit a form to redeem a coupon twice
  7. ACCOUNT ENUMERATION: Login error difference reveals valid usernames
  8. INSECURE DIRECT ACTION: Perform admin actions without admin role
  9. FORCED BROWSING: Access pages that should only be reachable via proper flow

Real-world examples:
  - Starbucks bug bounty: negative dollar gift card reload
  - Multiple e-commerce: negative quantity to reverse charge
  - Banks: concurrent requests to transfer same funds twice (race condition)
  - Social networks: mass assignment → is_admin: true in update endpoint

Detection approach (passive + minimal active probing):
  - Test login for username enumeration via different error messages
  - Check if account-scoped parameters can be tampered
  - Test mass assignment on common API endpoints
  - Detect inconsistent error messages that reveal user existence
"""

from __future__ import annotations
import json
import re
import time
from typing import List, Optional
from urllib.parse import urlparse
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

# ─── Account Enumeration ──────────────────────────────────────────────────────
# Different responses for valid vs invalid user = enumeration vulnerability
VALID_USER_SIGNALS = [
    "incorrect password", "wrong password", "invalid password",
    "password is incorrect", "password does not match",
    "password mismatch", "password",  # broad catch
]

INVALID_USER_SIGNALS = [
    "user not found", "account not found", "no account",
    "email not registered", "not a registered", "does not exist",
    "unknown email", "invalid email", "email not found",
    "not found in our system", "no user",
]

GENERIC_SIGNALS = [
    "invalid credentials", "login failed", "authentication failed",
    "incorrect username or password", "invalid username or password",
]

LOGIN_PATHS = [
    "/login", "/signin", "/api/login", "/api/auth",
    "/api/v1/login", "/api/v1/auth/login",
]

REGISTER_PATHS = [
    "/register", "/signup", "/api/register",
    "/api/v1/register", "/api/v1/users",
]

# ─── Mass Assignment Test ─────────────────────────────────────────────────────
MASS_ASSIGN_FIELDS = [
    {"role": "admin"},
    {"is_admin": True},
    {"admin": True},
    {"isAdmin": True},
    {"user_role": "admin"},
    {"permission": "admin"},
    {"permissions": ["admin", "superuser"]},
    {"account_type": "premium"},
    {"subscription": "enterprise"},
    {"verified": True},
    {"email_verified": True},
    {"balance": 99999},
    {"credits": 99999},
]

UPDATE_PATHS = [
    "/api/user", "/api/v1/user", "/api/me", "/api/v1/me",
    "/api/profile", "/api/v1/profile", "/api/account",
    "/user/update", "/profile/update", "/settings",
]


def _test_username_enumeration(client, base: str, findings: List[Finding]) -> None:
    """
    Test if the login endpoint reveals whether an email exists
    through different error messages.
    """
    for path in LOGIN_PATHS:
        login_url = base + path
        try:
            # Test with obviously fake email
            r1 = client.post(
                login_url,
                json={
                    "email": "definitely_not_real_xyz123@nonexistent-domain-test.invalid",
                    "password": "wrongpassword",
                    "username": "definitely_not_real_xyz123",
                },
            )

            # Test with several common usernames/emails that might exist
            found_existing = False
            r2 = None
            for candidate_user, candidate_email in [
                ("admin",      "admin@" + urlparse(base).netloc.split(":")[0]),
                ("administrator", "administrator@example.com"),
                ("test",       "test@example.com"),
                ("user",       "user@example.com"),
                ("alice",      "alice@example.com"),
            ]:
                try:
                    r2 = client.post(
                        login_url,
                        json={"email": candidate_email,
                              "password": "wrongpassword",
                              "username": candidate_user},
                    )
                    body2_check = r2.text.lower()
                    # If we got a password-specific error, this user exists
                    if any(s in body2_check for s in VALID_USER_SIGNALS):
                        found_existing = True
                        break
                    # If we got a DIFFERENT response than r1, user may exist
                    if r2.text.lower() != r1.text.lower():
                        found_existing = True
                        break
                except Exception:
                    continue
            if r2 is None:
                continue

            if r1.status_code not in (200, 400, 401, 403, 422):
                continue

            body1 = r1.text.lower()
            body2 = r2.text.lower()

            # Check for user-existence leaking messages
            body2 = r2.text.lower() if r2 else ""
            has_invalid_user1 = any(s in body1 for s in INVALID_USER_SIGNALS)
            has_valid_user2 = any(s in body2 for s in VALID_USER_SIGNALS) if body2 else False
            has_invalid_user2 = any(s in body2 for s in INVALID_USER_SIGNALS) if body2 else False
            responses_differ = body1.strip() != body2.strip() if body2 else False

            # Enumeration confirmed if:
            # 1. r1 says user not found but r2 says wrong password
            # 2. r1 says user not found but r2 has different message
            if found_existing and has_invalid_user1 and responses_differ:
                # Find what's different
                diff_signal = next((s for s in INVALID_USER_SIGNALS if s in body1), "")
                findings.append(Finding(
                    title=f"Username/Email Enumeration via Login Error: {path}",
                    severity=Severity.MEDIUM,
                    description=(
                        f"The login endpoint at '{path}' reveals whether an email address "
                        "is registered in the system through different error messages. "
                        "This allows attackers to build a list of valid accounts for "
                        "targeted phishing or credential stuffing attacks."
                    ),
                    evidence=(
                        f"Endpoint: {login_url}\n"
                        f"Non-existent user response: '{body1[:100]}'\n"
                        f"Potential existing user response: '{body2[:100]}'\n"
                        f"Signal: '{diff_signal}'"
                    ),
                    remediation=(
                        "Return identical error messages for invalid username AND invalid password: "
                        "'Invalid username or password' — never distinguish between them. "
                        "Use constant-time comparison to prevent timing-based enumeration too."
                    ),
                    code_fix=(
                        "# ❌ VULNERABLE — different messages reveal account existence:\n"
                        "if not user:\n"
                        "    return 'Account not found'\n"
                        "if not verify_password(password, user.hash):\n"
                        "    return 'Incorrect password'\n\n"
                        "# ✅ SAFE — identical message always:\n"
                        "user = User.get(email=email)\n"
                        "# Always check password (even if user doesn't exist — use dummy)\n"
                        "dummy_hash = '$2b$12$dummyhashforconstanttiming.....'\n"
                        "check_hash = user.password_hash if user else dummy_hash\n"
                        "if not user or not verify_password(password, check_hash):\n"
                        "    return 'Invalid username or password'  # always same message"
                    ),
                    reference="https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account",
                    cvss=5.3,
                ))
                return

        except Exception:
            continue


def _test_registration_enumeration(client, base: str, findings: List[Finding]) -> None:
    """Test if registration reveals existing accounts."""
    for path in REGISTER_PATHS:
        url = base + path
        try:
            # Try to register an obviously unlikely email
            r = client.post(
                url,
                json={
                    "email": "definitely_not_real_xyz123@nonexistent-domain.invalid",
                    "password": "TestPass123!",
                    "username": "definitely_not_real_xyz123",
                    "name": "Test User",
                },
            )

            if r.status_code not in (200, 201, 400, 409, 422):
                continue

            body = r.text.lower()
            # 409 Conflict or "already registered" messages
            if r.status_code == 409 or any(s in body for s in [
                "already registered", "already exists", "already taken",
                "email in use", "account exists"
            ]):
                findings.append(Finding(
                    title=f"Account Existence Revealed via Registration: {path}",
                    severity=Severity.LOW,
                    description=(
                        f"The registration endpoint '{path}' reveals whether an email "
                        "is already registered. While expected behavior, it enables "
                        "account enumeration. Consider mitigating with email verification flow."
                    ),
                    evidence=(
                        f"Endpoint: {url}\n"
                        f"HTTP {r.status_code} with message: {body[:100]}"
                    ),
                    remediation=(
                        "Consider always returning success and sending a verification email "
                        "(whether or not the account exists). "
                        "The email itself tells the real user what happened."
                    ),
                    reference="https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account",
                    cvss=3.7,
                ))
                return

        except Exception:
            continue


def _test_mass_assignment(client, base: str, findings: List[Finding]) -> None:
    """
    Test if API endpoints accept unexpected privileged fields.
    Mass assignment = server binds all request fields to model without filtering.
    """
    for path in UPDATE_PATHS[:5]:
        url = base + path
        for extra_fields in MASS_ASSIGN_FIELDS[:5]:
            try:
                # PATCH/PUT with extra privileged fields
                payload = {
                    "name": "Test User",
                    "email": "test@example.com",
                    **extra_fields,
                }
                r = client.patch(url, json=payload)
                if r.status_code not in (200, 201, 204):
                    r = client.put(url, json=payload)

                if r.status_code in (200, 201, 204):
                    body = r.text.lower()
                    # Check if the extra field appears accepted in response
                    for field, value in extra_fields.items():
                        field_in_response = field.lower() in body
                        value_in_response = str(value).lower() in body
                        if field_in_response and value_in_response:
                            findings.append(Finding(
                                title=f"Mass Assignment — Privileged Field Accepted: {field}={value}",
                                severity=Severity.HIGH,
                                description=(
                                    f"The API endpoint '{path}' accepted the field '{field}={value}' "
                                    "and reflected it in the response. This suggests mass assignment "
                                    "vulnerability — attackers can escalate privileges by including "
                                    "extra fields in update requests."
                                ),
                                evidence=(
                                    f"Endpoint: {url}\n"
                                    f"Payload: {json.dumps(payload)}\n"
                                    f"Response contains: {field}={value}\n"
                                    f"Response: {r.text[:200]}"
                                ),
                                remediation=(
                                    "Use an explicit allowlist of accepted fields. "
                                    "Never bind all request fields to model automatically. "
                                    "Use DTOs (Data Transfer Objects) with only permitted fields."
                                ),
                                code_fix=(
                                    "# ❌ VULNERABLE (Django):\n"
                                    "user.update(**request.data)  # accepts everything\n\n"
                                    "# ✅ SAFE — explicit field allowlist:\n"
                                    "ALLOWED_UPDATE_FIELDS = {'name', 'email', 'bio'}\n"
                                    "safe_data = {k: v for k, v in request.data.items()\n"
                                    "             if k in ALLOWED_UPDATE_FIELDS}\n"
                                    "user.update(**safe_data)\n\n"
                                    "# ✅ FastAPI — Pydantic model (only defined fields accepted):\n"
                                    "class UserUpdate(BaseModel):\n"
                                    "    name: Optional[str]\n"
                                    "    email: Optional[str]\n"
                                    "    # is_admin NOT here — cannot be set by user"
                                ),
                                reference="https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html",
                                cvss=8.8,
                            ))
                            return

            except Exception:
                continue


def _test_forced_browsing(client, base: str, findings: List[Finding]) -> None:
    """Test for forced browsing — accessing pages that should require prior steps."""
    forced_paths = [
        # Checkout steps
        ("/checkout/confirm", "/checkout"),
        ("/checkout/complete", "/checkout"),
        ("/order/confirm", "/cart"),
        # Password reset completion without token
        ("/password/reset/confirm", "/login"),
        ("/reset-password?step=2", "/reset-password"),
        # Admin functions
        ("/admin/users", "/admin"),
        ("/admin/settings", "/admin"),
    ]

    for (target_path, expected_prior) in forced_paths[:4]:
        try:
            r = client.get(base + target_path)
            if r.status_code == 200:
                body = r.text.lower()
                # Check if it looks like a functional page (not just a redirect/error)
                if len(body) > 200 and not any(kw in body for kw in
                                                ["login", "sign in", "unauthorized",
                                                 "access denied", "forbidden"]):
                    findings.append(Finding(
                        title=f"Possible Forced Browsing — Step Bypass: {target_path}",
                        severity=Severity.MEDIUM,
                        description=(
                            f"The endpoint '{target_path}' returned HTTP 200 without going through "
                            f"'{expected_prior}' first. This may indicate forced browsing / workflow "
                            "bypass vulnerability. Manual verification required."
                        ),
                        evidence=(
                            f"Direct access to: {base + target_path}\n"
                            f"HTTP 200 returned ({len(body)} bytes)\n"
                            f"Expected prior step: {expected_prior}"
                        ),
                        remediation=(
                            "Enforce server-side state checks at each step. "
                            "Don't rely on client-side navigation to enforce process flow. "
                            "Validate prerequisites before executing any step."
                        ),
                        code_fix=(
                            "# Server-side workflow state validation:\n"
                            "@app.route('/checkout/confirm', methods=['POST'])\n"
                            "@login_required\n"
                            "def checkout_confirm():\n"
                            "    # Verify cart exists and payment was processed\n"
                            "    if not session.get('payment_verified'):\n"
                            "        return redirect('/checkout'), 302\n"
                            "    # proceed..."
                        ),
                        reference="https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/06-Testing_for_Bypass_of_Work_Flow",
                        cvss=5.3,
                    ))
                    break

        except Exception:
            continue


def scan(url: str, timeout: float = 12.0) -> List[Finding]:
    findings: List[Finding] = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    with get_client(timeout=min(timeout, 10.0)) as client:
        # 1. Account enumeration via login
        _test_username_enumeration(client, base, findings)

        # 2. Account enumeration via registration
        _test_registration_enumeration(client, base, findings)

        # 3. Mass assignment
        _test_mass_assignment(client, base, findings)

        # 4. Forced browsing / workflow bypass
        _test_forced_browsing(client, base, findings)

    return findings
