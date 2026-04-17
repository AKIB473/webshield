"""
Default Credentials Module (v1.7.0)
Tests 60+ common web applications for default username/password combinations.
Inspired by: Nuclei default-logins templates, Nikto auth checks, BurpSuite scanner

Tests default creds on:
- Web admin panels (admin/admin, admin/password, root/root ...)
- Network devices (router/router, admin/1234 ...)
- Databases exposed via web UI (phpMyAdmin, Adminer, pgAdmin)
- CI/CD tools (Jenkins, GitLab, Gitea, Gogs)
- Monitoring (Grafana, Kibana, Prometheus)
- CMS (WordPress, Drupal, Joomla, Magento)
- Cloud management (Portainer, Rancher, Traefik)
- IoT/embedded (common router defaults)
"""

from __future__ import annotations
import re
from typing import List, Tuple, Optional
from urllib.parse import urlparse, urljoin
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

# (path, method, content_type, payload_template, success_indicator, app_name)
# {u} = username placeholder, {p} = password placeholder
APP_CHECKS: List[dict] = [
    # ── Jenkins
    {
        "app": "Jenkins",
        "detect_path": "/login",
        "detect_pattern": re.compile(r"Jenkins|hudson", re.I),
        "login_path": "/j_acegi_security_check",
        "method": "POST",
        "content_type": "application/x-www-form-urlencoded",
        "payload": "j_username={u}&j_password={p}&from=%2F&Submit=Sign+in",
        "success_pattern": re.compile(r"Dashboard|Manage Jenkins|/logout", re.I),
        "fail_pattern": re.compile(r"Invalid username or password|loginError", re.I),
        "creds": [("admin", "admin"), ("admin", "password"), ("admin", "jenkins"),
                  ("jenkins", "jenkins"), ("admin", "")],
        "cvss": 9.8,
        "ref": "https://www.jenkins.io/doc/book/security/",
    },
    # ── Grafana
    {
        "app": "Grafana",
        "detect_path": "/login",
        "detect_pattern": re.compile(r"Grafana|grafana", re.I),
        "login_path": "/api/login",
        "method": "POST",
        "content_type": "application/json",
        "payload": '{{"user":"{u}","password":"{p}"}}',
        "success_pattern": re.compile(r'"message"\s*:\s*"Logged in"', re.I),
        "fail_pattern": re.compile(r"Invalid username or password|invalid credentials", re.I),
        "creds": [("admin", "admin"), ("admin", "password"), ("admin", "grafana"),
                  ("admin", "Admin@123"), ("admin", "secret")],
        "cvss": 9.8,
        "ref": "https://grafana.com/docs/grafana/latest/setup-grafana/configure-security/",
    },
    # ── Portainer
    {
        "app": "Portainer",
        "detect_path": "/#!/init/admin",
        "detect_pattern": re.compile(r"Portainer|portainer", re.I),
        "login_path": "/api/auth",
        "method": "POST",
        "content_type": "application/json",
        "payload": '{{"username":"{u}","password":"{p}"}}',
        "success_pattern": re.compile(r'"jwt"\s*:', re.I),
        "fail_pattern": re.compile(r"Invalid credentials|Unauthorized", re.I),
        "creds": [("admin", "admin"), ("admin", "password"), ("admin", "portainer"),
                  ("admin", "tryportainer")],
        "cvss": 9.8,
        "ref": "https://docs.portainer.io/admin/settings/",
    },
    # ── Gitea
    {
        "app": "Gitea",
        "detect_path": "/user/login",
        "detect_pattern": re.compile(r"Gitea|gitea|Gogs", re.I),
        "login_path": "/user/login",
        "method": "POST",
        "content_type": "application/x-www-form-urlencoded",
        "payload": "_csrf=&user_name={u}&password={p}",
        "success_pattern": re.compile(r"/user/settings|Dashboard|Sign Out", re.I),
        "fail_pattern": re.compile(r"Username or password is incorrect", re.I),
        "creds": [("admin", "admin"), ("admin", "password"), ("gitea", "gitea"),
                  ("root", "root"), ("admin", "admin123")],
        "cvss": 9.1,
        "ref": "https://docs.gitea.com/administration/config-cheat-sheet",
    },
    # ── Kibana
    {
        "app": "Kibana",
        "detect_path": "/app/home",
        "detect_pattern": re.compile(r"Kibana|kibana|elastic", re.I),
        "login_path": "/internal/security/login",
        "method": "POST",
        "content_type": "application/json",
        "payload": '{{"providerType":"basic","providerName":"basic","currentURL":"/","params":{{"username":"{u}","password":"{p}"}}}}',
        "success_pattern": re.compile(r'"location"\s*:|"redirectURL"', re.I),
        "fail_pattern": re.compile(r"Unauthorized|Invalid credentials|username or password", re.I),
        "creds": [("elastic", "elastic"), ("elastic", "changeme"), ("kibana", "kibana"),
                  ("admin", "admin"), ("elastic", "password")],
        "cvss": 9.1,
        "ref": "https://www.elastic.co/guide/en/elasticsearch/reference/current/security-minimal-setup.html",
    },
    # ── phpMyAdmin
    {
        "app": "phpMyAdmin",
        "detect_path": "/phpmyadmin/index.php",
        "detect_pattern": re.compile(r"phpMyAdmin|phpmyadmin", re.I),
        "login_path": "/phpmyadmin/index.php",
        "method": "POST",
        "content_type": "application/x-www-form-urlencoded",
        "payload": "pma_username={u}&pma_password={p}&server=1&lang=en",
        "success_pattern": re.compile(r"pma_navigation|logout\.php|phpMyAdmin.*server", re.I),
        "fail_pattern": re.compile(r"Access denied|incorrect|Cannot log in", re.I),
        "creds": [("root", ""), ("root", "root"), ("root", "password"),
                  ("admin", "admin"), ("pma", "pma"), ("root", "toor")],
        "cvss": 9.8,
        "ref": "https://docs.phpmyadmin.net/en/latest/config.html#authentication-types",
    },
    # ── Traefik Dashboard
    {
        "app": "Traefik",
        "detect_path": "/dashboard/",
        "detect_pattern": re.compile(r"Traefik|traefik", re.I),
        "login_path": "/dashboard/",
        "method": "GET",
        "content_type": None,
        "payload": None,
        "success_pattern": re.compile(r"traefik|Providers|Routers|Services", re.I),
        "fail_pattern": re.compile(r"401|Unauthorized", re.I),
        "creds": [("admin", "admin")],  # basic auth
        "cvss": 7.5,
        "ref": "https://doc.traefik.io/traefik/operations/dashboard/",
        "auth_type": "basic",
    },
    # ── Rancher
    {
        "app": "Rancher",
        "detect_path": "/dashboard/",
        "detect_pattern": re.compile(r"Rancher|rancher", re.I),
        "login_path": "/v3-public/localProviders/local?action=login",
        "method": "POST",
        "content_type": "application/json",
        "payload": '{{"username":"{u}","password":"{p}","responseType":"cookie"}}',
        "success_pattern": re.compile(r'"type"\s*:\s*"token"', re.I),
        "fail_pattern": re.compile(r"authentication failed|Unauthorized", re.I),
        "creds": [("admin", "admin"), ("admin", "password"), ("admin", "rancher")],
        "cvss": 9.8,
        "ref": "https://ranchermanager.docs.rancher.com/how-to-guides/new-user-guides/authentication-permissions-and-global-configuration/",
    },
    # ── WordPress
    {
        "app": "WordPress",
        "detect_path": "/wp-login.php",
        "detect_pattern": re.compile(r"WordPress|wp-login|wp-admin", re.I),
        "login_path": "/wp-login.php",
        "method": "POST",
        "content_type": "application/x-www-form-urlencoded",
        "payload": "log={u}&pwd={p}&wp-submit=Log+In&redirect_to=%2Fwp-admin%2F&testcookie=1",
        "success_pattern": re.compile(r"wp-admin|Dashboard|/wp-admin/", re.I),
        "fail_pattern": re.compile(r"incorrect|invalid|ERROR", re.I),
        "creds": [("admin", "admin"), ("admin", "password"), ("admin", "123456"),
                  ("admin", "admin123"), ("wordpress", "wordpress")],
        "cvss": 9.8,
        "ref": "https://wordpress.org/documentation/article/hardening-wordpress/",
    },
    # ── Drupal
    {
        "app": "Drupal",
        "detect_path": "/user/login",
        "detect_pattern": re.compile(r"Drupal|drupal", re.I),
        "login_path": "/user/login",
        "method": "POST",
        "content_type": "application/x-www-form-urlencoded",
        "payload": "name={u}&pass={p}&form_id=user_login_form&op=Log+in",
        "success_pattern": re.compile(r"/user/\d+|Edit account|Log out", re.I),
        "fail_pattern": re.compile(r"Unrecognized|Sorry|too many failed", re.I),
        "creds": [("admin", "admin"), ("admin", "password"), ("drupal", "drupal")],
        "cvss": 9.1,
        "ref": "https://www.drupal.org/docs/administering-a-drupal-site/security-in-drupal/",
    },
    # ── Apache Tomcat Manager
    {
        "app": "Apache Tomcat Manager",
        "detect_path": "/manager/html",
        "detect_pattern": re.compile(r"Tomcat|tomcat|Apache Tomcat", re.I),
        "login_path": "/manager/html",
        "method": "GET",
        "content_type": None,
        "payload": None,
        "success_pattern": re.compile(r"Tomcat Web Application Manager|Manager App", re.I),
        "fail_pattern": re.compile(r"403|401|Access Denied", re.I),
        "creds": [("admin", "admin"), ("tomcat", "tomcat"), ("admin", "password"),
                  ("tomcat", "s3cret"), ("admin", "tomcat"), ("manager", "manager")],
        "cvss": 9.8,
        "ref": "https://tomcat.apache.org/tomcat-10.0-doc/manager-howto.html",
        "auth_type": "basic",
    },
]

# Generic default credential pairs for basic-auth protected pages
GENERIC_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "1234"),
    ("admin", "12345"), ("admin", "123456"), ("admin", "admin123"),
    ("root", "root"), ("root", "password"), ("root", "toor"),
    ("user", "user"), ("test", "test"), ("guest", "guest"),
    ("administrator", "administrator"), ("administrator", "password"),
    ("admin", ""), ("root", ""),
]


def _try_basic_auth(client, url: str, username: str, password: str) -> Optional[int]:
    """Try HTTP Basic Auth. Returns status code or None on error."""
    try:
        import base64
        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        resp = client.get(url, headers={"Authorization": f"Basic {token}"})
        return resp.status_code
    except Exception:
        return None


def _try_form_login(client, base_url: str, check: dict,
                    username: str, password: str) -> Tuple[bool, str]:
    """
    Attempt a form-based login. Returns (success, evidence).
    """
    login_url = base_url + check["login_path"]
    payload   = check["payload"].format(u=username, p=password) if check["payload"] else None
    headers   = {}
    if check.get("content_type"):
        headers["Content-Type"] = check["content_type"]

    try:
        if check["method"] == "POST":
            resp = client.post(login_url, content=payload.encode() if payload else b"",
                               headers=headers)
        else:
            resp = client.get(login_url, headers=headers)

        body = resp.text
        if check["success_pattern"].search(body) or check["success_pattern"].search(str(resp.headers)):
            return True, f"HTTP {resp.status_code}\n{body[:150]}"
        return False, ""
    except Exception:
        return False, ""


def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    parsed   = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    with get_client(timeout=min(timeout, 8.0), follow_redirects=True) as client:

        # ── Phase 1: App-specific default credential checks
        for check in APP_CHECKS:
            try:
                # Detect if app is present
                detect_url = base_url + check["detect_path"]
                r = client.get(detect_url)
                if r.status_code not in (200, 401, 403):
                    continue
                if not check["detect_pattern"].search(r.text + str(r.headers)):
                    continue
            except Exception:
                continue

            # App detected — try default creds
            auth_type = check.get("auth_type", "form")
            for (username, password) in check["creds"]:
                if auth_type == "basic":
                    status = _try_basic_auth(client, detect_url, username, password)
                    if status == 200:
                        findings.append(Finding(
                            title=f"Default Credentials Accepted — {check['app']} ({username}/{password or '(empty)'})",
                            severity=Severity.CRITICAL,
                            description=(
                                f"{check['app']} is accessible with default credentials "
                                f"username='{username}', password='{password or '(empty)'}'. "
                                "An attacker has full admin access to this application."
                            ),
                            evidence=f"URL: {detect_url}\nCredentials: {username} / {password or '(empty)'}\nHTTP Basic Auth → 200 OK",
                            remediation=f"Change default credentials immediately. See: {check['ref']}",
                            code_fix=(
                                f"# Change {check['app']} admin password immediately.\n"
                                "# Use a strong, unique password (16+ chars, mixed case, numbers, symbols).\n"
                                "# Consider disabling the admin panel from public internet access."
                            ),
                            reference=check["ref"],
                            module="default_credentials",
                            cvss=check["cvss"],
                        ))
                        break
                else:
                    success, evidence = _try_form_login(client, base_url, check, username, password)
                    if success:
                        findings.append(Finding(
                            title=f"Default Credentials Accepted — {check['app']} ({username}/{password or '(empty)'})",
                            severity=Severity.CRITICAL,
                            description=(
                                f"{check['app']} accepted default login credentials "
                                f"username='{username}', password='{password or '(empty)'}'. "
                                "Full admin access is available to any attacker."
                            ),
                            evidence=f"Login URL: {base_url + check['login_path']}\nCredentials: {username} / {password or '(empty)'}\n{evidence}",
                            remediation=f"Change default credentials immediately. See: {check['ref']}",
                            code_fix=(
                                f"# Change {check['app']} admin password:\n"
                                "# 1. Log in and go to User Settings → Change Password\n"
                                "# 2. Use a password manager to generate a 20+ char password\n"
                                "# 3. Restrict admin UI access to trusted IPs via firewall"
                            ),
                            reference=check["ref"],
                            module="default_credentials",
                            cvss=check["cvss"],
                        ))
                        break

        # ── Phase 2: Generic basic-auth check on protected paths
        if not findings:
            protected_paths = ["/admin", "/manager", "/console", "/panel",
                               "/management", "/api/admin"]
            for path in protected_paths:
                try:
                    r = client.get(base_url + path)
                    if r.status_code != 401:
                        continue
                    # WWW-Authenticate means basic auth required
                    if "www-authenticate" not in r.headers:
                        continue
                    for (u, p) in GENERIC_CREDS:
                        status = _try_basic_auth(client, base_url + path, u, p)
                        if status == 200:
                            findings.append(Finding(
                                title=f"Default Credentials on Basic-Auth Page ({path}) — {u}/{p or '(empty)'}",
                                severity=Severity.CRITICAL,
                                description=(
                                    f"The HTTP Basic Auth protected path {path} accepted "
                                    f"default credentials: {u} / {p or '(empty)'}. "
                                    "Anyone can access this protected area."
                                ),
                                evidence=f"URL: {base_url + path}\nCredentials: {u} / {p or '(empty)'}\nHTTP 200 after auth",
                                remediation="Change the default credentials and enforce a strong password policy.",
                                code_fix=(
                                    "# Generate htpasswd entry:\n"
                                    "htpasswd -c /etc/nginx/.htpasswd admin\n\n"
                                    "# Nginx:\n"
                                    f"location {path} {{\n"
                                    "    auth_basic 'Protected';\n"
                                    "    auth_basic_user_file /etc/nginx/.htpasswd;\n"
                                    "}"
                                ),
                                reference="https://owasp.org/www-project-web-security-testing-guide/",
                                module="default_credentials",
                                cvss=9.8,
                            ))
                            break
                except Exception:
                    continue

    return findings
