"""
Rate Limiting & Brute Force Protection Module
Tests login/API endpoints for missing rate limiting.
NEW in v1.1.0
"""

from __future__ import annotations
import time
from typing import List
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

LOGIN_PATHS = [
    "/login", "/signin", "/auth", "/api/login", "/api/auth",
    "/user/login", "/account/login", "/wp-login.php",
    "/admin/login", "/api/v1/auth", "/api/v1/login",
]

PROBE_CREDENTIALS = [
    ("test@example.com", "wrongpassword1"),
    ("test@example.com", "wrongpassword2"),
    ("test@example.com", "wrongpassword3"),
    ("test@example.com", "wrongpassword4"),
    ("test@example.com", "wrongpassword5"),
]


def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    base = url.rstrip("/")

    with get_client(timeout=min(timeout, 6.0)) as client:
        for path in LOGIN_PATHS:
            login_url = base + path
            try:
                resp = client.get(login_url)
                if resp.status_code not in (200, 401, 403):
                    continue
                if len(resp.text.strip()) < 50:
                    continue

                # Found a potential login endpoint — test rate limiting
                statuses = []
                last_status = None
                blocked = False

                for i, (email, pwd) in enumerate(PROBE_CREDENTIALS):
                    try:
                        r = client.post(
                            login_url,
                            data={"email": email, "password": pwd,
                                  "username": email, "user": email},
                            headers={"Content-Type": "application/x-www-form-urlencoded"},
                        )
                        statuses.append(r.status_code)

                        # Check for rate limit response codes
                        if r.status_code in (429, 423, 503):
                            blocked = True
                            break

                        # Check for CAPTCHA in response
                        body_lower = r.text.lower()
                        if any(kw in body_lower for kw in
                               ["captcha", "rate limit", "too many", "slow down",
                                "locked", "blocked", "throttl"]):
                            blocked = True
                            break

                        time.sleep(0.3)  # be polite
                    except Exception:
                        break

                if blocked or len(statuses) < 3:
                    # Rate limiting is working or endpoint didn't respond consistently
                    findings.append(Finding(
                        title=f"Login Endpoint Found with Rate Limiting: {path}",
                        severity=Severity.INFO,
                        description=f"Login endpoint at {path} appears to have rate limiting or CAPTCHA protection.",
                        evidence=f"Response codes: {statuses}",
                    ))
                else:
                    # All 5 requests went through with same status
                    if all(s in (200, 401, 403) for s in statuses) and len(set(statuses)) == 1:
                        findings.append(Finding(
                            title=f"Login Endpoint Missing Rate Limiting: {path}",
                            severity=Severity.MEDIUM,
                            description=(
                                f"The login endpoint at {path} does not appear to have "
                                "rate limiting. 5 consecutive failed login attempts all "
                                "returned HTTP {statuses[0]} without any throttling. "
                                "Attackers can brute-force credentials without restriction."
                            ),
                            evidence=(
                                f"Endpoint: {login_url}\n"
                                f"5 probe requests, all returned: {statuses[0]}\n"
                                "No 429, CAPTCHA, or lockout detected."
                            ),
                            remediation=(
                                "Implement rate limiting on authentication endpoints. "
                                "Lock accounts after 5-10 failed attempts. "
                                "Use CAPTCHA or exponential backoff."
                            ),
                            code_fix=(
                                "# Python (Flask-Limiter):\n"
                                "from flask_limiter import Limiter\n"
                                "limiter = Limiter(app, key_func=get_remote_address)\n\n"
                                "@app.route('/login', methods=['POST'])\n"
                                "@limiter.limit('5 per minute')\n"
                                "def login(): ...\n\n"
                                "# Django (django-ratelimit):\n"
                                "@ratelimit(key='ip', rate='5/m', block=True)\n"
                                "def login(request): ...\n\n"
                                "# Node.js (express-rate-limit):\n"
                                "const limiter = rateLimit({ windowMs: 60000, max: 5 });\n"
                                "app.use('/login', limiter);"
                            ),
                            reference="https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
                            cvss=7.3,
                        ))
                        return findings  # one finding per site is enough

            except Exception:
                continue

    return findings
