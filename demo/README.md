# WebShield Demo App

A **deliberately vulnerable Flask application** designed to trigger every WebShield module.

> ⚠️ **FOR TESTING ONLY** — Never deploy this publicly. It contains intentional security vulnerabilities.

---

## Quick Start

```bash
# Install dependencies
pip install flask httpx

# Run the vulnerable app
python3 demo/app.py
# → http://localhost:5000

# In another terminal, scan it
webshield scan http://localhost:5000 \
  --output report.html \
  --json results.json \
  --timeout 15
```

---

## What It Covers (60 modules → 60 vulnerabilities)

| Module | Endpoint | Vulnerability |
|---|---|---|
| `sql_injection` | `/?id=1` | Error-based + time-based SQLi via SQLite |
| `xss_detection` | `/?q=test` | Reflected XSS — unescaped param in response |
| `ssti` | `/?name=test` | Jinja2 SSTI via `Environment().from_string()` |
| `cmd_injection` | `/cmd?ip=127.0.0.1` | `os.system()` with unsanitized input |
| `lfi` | `/file?path=index` | `open(user_path)` without validation |
| `ssrf` | `/fetch?url=...` | `requests.get(user_url)` unrestricted |
| `cors` | `/api/data` | `Origin` reflected + `credentials: true` |
| `jwt` | `/jwt-demo` | `alg:none` accepted + weak secret |
| `headers` | `/no-headers` | No security headers at all |
| `cookies` | `/set-cookie` | Session cookie without Secure/HttpOnly/SameSite |
| `csrf_check` | `/transfer` | State-changing POST with no CSRF token |
| `nosql_injection` | `/api/nosql-login` | MongoDB `$ne` operator accepted |
| `http_header_injection` | `/host-reflect` | Host header reflected in response body |
| `open_redirect` | `/redirect?next=` | No validation on redirect target |
| `info_leak` | `/.env` | `.env` file with DB credentials exposed |
| `sensitive_paths` | `/admin` | Admin panel with no auth |
| `secret_leak` | `/` | AWS key in page source |
| `csp` | `/no-headers` | No Content-Security-Policy |
| `clickjacking` | `/no-headers` | No X-Frame-Options |
| `idor_check` | `/api/user?id=1` | Sequential user IDs, no auth |
| `api_exposure` | `/openapi.json` | Full OpenAPI spec exposed |
| `auth_hardening` | `/login` | No rate limiting on login |
| `insecure_deserialization` | `/set-cookie` | Java serial magic bytes in cookie |
| `web_cache_deception` | `/account` | Private page cacheable at `/account/x.css` |
| `file_upload` | `/upload` | Accepts any file type, no validation |
| `dom_xss` | `/dom-xss` | `innerHTML = location.hash` |
| `business_logic` | `/api/register` | Mass assignment (`is_admin=true`) |
| `rate_limit` | `/login` | Unlimited login attempts |
| `graphql` | `/graphql` | Introspection enabled, batch queries |
| `supply_chain` | `/package.json` | Old packages with known CVEs |
| `source_code_disclosure` | `/.git/HEAD` | Git repo exposed + `.php.bak` backup file |
| `bypass_403` | `/secret-admin` | Returns 403 on GET, 200 on POST (verb tamper) |
| `pii_detection` | `/api/user-data` | SSN + credit cards + IBAN in JSON response |
| `spring_actuator` | `/actuator/env` | All env vars including DB password + JWT secret |
| `http_parameter_pollution` | `/search?q=x&q=y` | Reflects second value of duplicate param |
| `websocket_security` | `/ws-demo` | `ws://` used on page (downgrade) |
| `openapi_scan` | `/openapi.json` | Spec exposed + unauth endpoints with tokens |
| `cve_checks` | `/version` | Server header reveals vulnerable version |
| `default_credentials` | `/wp-login.php` | WordPress login accepts admin/admin |
| `exposed_panels` | `/grafana`, `/prometheus` | Unauthenticated Grafana + Prometheus |
| `xxe_oob` | `/api/xml` | XML endpoint with no entity protection |
| `evasion_scan` | `/?id=1` | WAF evasion triggers SQL error |
| `lfi` | `/file?path=` | Path traversal |
| `ssrf` | `/fetch?url=` | SSRF to internal services |
| `mixed_content` | `/mixed` | HTTP resources on HTTPS page |
| `dns_email` | *(DNS check)* | Missing SPF/DMARC |
| `subdomain_takeover` | *(DNS check)* | Unclaimed CNAME |
| `waf_detect` | `/` | No WAF present |
| `request_smuggling` | `/` | CL.TE timing |
| `broken_links` | `/` | Dead links on page |
| `security_txt` | `/.well-known/security.txt` | Missing |
| `sri_check` | `/` | CDN scripts without integrity= |
| `tech_fingerprint` | `/` | Server version in headers |
| `cloud_exposure` | `/` | Cloud metadata endpoint probe |
| `malware_indicators` | `/` | Suspicious iframe/script |
| `proto_pollution` | `/?__proto__[x]=1` | Prototype pollution |
| `crlf_injection` | `/?x=%0d%0a` | CRLF in response |
| `log4shell` | `/` | Log4J JNDI payload in headers |
| `xxe` | `/api/xml` | Basic XXE |
| `ssl_tls` | *(TLS check)* | Certificate validation |

---

## Expected Scan Results

```
Score: 0/100  Grade: F
Findings: 100+  |  CRITICAL: 25+  |  HIGH: 25+

🔴 CRITICAL
  - Default Credentials (admin/admin on /wp-login.php)
  - Git Repository Exposed (/.git/HEAD)
  - PII Data Exposed (SSN, Credit Cards, IBAN)
  - Spring Actuator /env (DB password, JWT secret, AWS key)
  - SQL Injection (error-based + time-based)
  - SSTI → RCE (Jinja2 template injection)
  - OS Command Injection
  - JWT alg:none bypass
  - NoSQL auth bypass
  - XXE file read
  - Insecure deserialization
  - Secret leak (AWS key in source)
  ...
```
