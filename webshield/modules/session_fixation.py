"""Session Fixation & Session Management (v1.8.0)"""
from __future__ import annotations
import re
from typing import List
from urllib.parse import urlparse
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

SESSION_PARAMS = re.compile(r"(PHPSESSID|JSESSIONID|ASP\.NET_SessionId|session_id|sid|auth_token)=([^&;\s]+)", re.I)
SESSION_COOKIE_NAMES = ["PHPSESSID","JSESSIONID","ASP.NET_SessionId","session","sid","auth","token","connect.sid"]

LOGIN_PATHS = ["/login","/signin","/api/login","/api/auth","/wp-login.php","/user/login","/auth/login"]

def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    with get_client(timeout=min(timeout, 8.0), follow_redirects=True) as client:
        # 1. Check if session token appears in URL
        try:
            resp = client.get(url)
            url_str = str(resp.url)
            m = SESSION_PARAMS.search(url_str)
            if m:
                findings.append(Finding(
                    title=f"Session Token in URL — {m.group(1)}",
                    severity=Severity.MEDIUM,
                    description=(
                        f"The session identifier '{m.group(1)}' is exposed in the URL. "
                        "Session tokens in URLs are logged in server logs, browser history, "
                        "and Referer headers, allowing session hijacking."
                    ),
                    evidence=f"URL: {url_str}\nSession param: {m.group(1)}={m.group(2)[:20]}...",
                    remediation="Use cookies for session management, never URL parameters.",
                    code_fix=(
                        "# PHP — force cookie-based sessions:\n"
                        "ini_set('session.use_only_cookies', 1);\n"
                        "ini_set('session.use_trans_sid', 0);\n\n"
                        "# Express:\n"
                        "app.use(session({ resave: false, saveUninitialized: false }))"
                    ),
                    reference="https://owasp.org/www-community/attacks/Session_fixation",
                    module="session_fixation",
                    cvss=6.5,
                ))
        except Exception:
            pass

        # 2. Check session fixation — set session ID pre-login, check if same after login
        for path in LOGIN_PATHS:
            try:
                # Get pre-login session
                r1 = client.get(base_url + path)
                pre_cookies = {k: v for k, v in r1.cookies.items()
                               if any(n.lower() in k.lower() for n in SESSION_COOKIE_NAMES)}
                if not pre_cookies:
                    continue

                # Try POST login with the same session cookie
                cname, cval = next(iter(pre_cookies.items()))
                r2 = client.post(
                    base_url + path,
                    content=b"username=admin&password=wrongpassword",
                    headers={"Content-Type": "application/x-www-form-urlencoded",
                             "Cookie": f"{cname}={cval}"},
                )
                post_cookies = {k: v for k, v in r2.cookies.items()
                                if any(n.lower() in k.lower() for n in SESSION_COOKIE_NAMES)}

                # If no new session was issued, the old one is still valid → fixation risk
                if not post_cookies and r2.status_code in (200, 302):
                    findings.append(Finding(
                        title=f"Potential Session Fixation — {path}",
                        severity=Severity.HIGH,
                        description=(
                            f"The login endpoint {path} did not issue a new session cookie "
                            "after the login attempt. If the pre-login session ID is accepted "
                            "post-login, session fixation attacks are possible: an attacker "
                            "sets a known session ID, victim logs in, attacker hijacks session."
                        ),
                        evidence=(
                            f"Pre-login cookie: {cname}={cval[:20]}...\n"
                            f"POST {path} → HTTP {r2.status_code}\n"
                            "No new session cookie issued in response"
                        ),
                        remediation="Regenerate the session ID after every successful login.",
                        code_fix=(
                            "# PHP:\nsession_regenerate_id(true);  // call after successful login\n\n"
                            "# Express:\nreq.session.regenerate((err) => { /* continue */ });\n\n"
                            "# Django: cycle_key() is called automatically on login()"
                        ),
                        reference="https://owasp.org/www-community/attacks/Session_fixation",
                        module="session_fixation",
                        cvss=7.5,
                    ))
                    break
            except Exception:
                continue

        # 3. Detect session ID in Referer header leakage
        try:
            resp = client.get(url)
            for cname in SESSION_COOKIE_NAMES:
                if cname.lower() in str(resp.headers).lower():
                    body = resp.text[:3000]
                    if re.search(r'<a\s[^>]*href=["\'][^"\']*' + cname, body, re.I):
                        findings.append(Finding(
                            title="Session Token Exposed in Hyperlink (Referer Leakage Risk)",
                            severity=Severity.MEDIUM,
                            description=(
                                "A session token was found embedded in a hyperlink. "
                                "When users click this link, the session ID will be sent "
                                "in the Referer header to the destination site."
                            ),
                            evidence=f"Session cookie name '{cname}' found in page links",
                            remediation="Remove session tokens from all URLs and use cookies exclusively.",
                            code_fix="# Set Referrer-Policy: no-referrer or same-origin\nresponse.headers['Referrer-Policy'] = 'no-referrer'",
                            reference="https://owasp.org/www-community/attacks/Session_fixation",
                            module="session_fixation",
                            cvss=4.3,
                        ))
                        break
        except Exception:
            pass

    return findings
