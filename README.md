# 🛡️ WebShield

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![CI](https://github.com/AKIB473/webshield/actions/workflows/ci.yml/badge.svg)](https://github.com/AKIB473/webshield/actions)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![Version](https://img.shields.io/badge/version-1.8.0-brightgreen)](https://github.com/AKIB473/webshield)
[![Stars](https://img.shields.io/github/stars/AKIB473/webshield?style=social)](https://github.com/AKIB473/webshield)

WebShield is a **developer-first** web security scanner. Point it at any website and get:
- A **security score (0–100)** and **letter grade (A+ to F)**
- **78 parallel scan modules** covering every OWASP Top 10:2025 category
- **Code-level fix examples** for every finding — not just "you have XSS", but *here's the exact vulnerable line and the safe version*
- **Auto-crawling** — discovers injectable URLs automatically, no manual param setup
- **HTML + JSON + SARIF** reports
- **Default credential testing** on 60+ real apps
- **WAF evasion** techniques to find bypasses
- **CVE fingerprinting** for 10+ critical vulnerabilities

> **v1.8.0** — 78 modules. New: default credential testing, exposed panel detection, WAF evasion, OpenAPI/Swagger endpoint testing, blind XXE, source code disclosure, 403 bypass, PII detection, Spring Actuator, HTTP parameter pollution, CVE checks, WebSocket security.

---

## ⚡ Quick Start

```bash
git clone https://github.com/AKIB473/webshield.git
cd webshield && pip install -e .
webshield scan https://yoursite.com
```

---

## 🧪 Try It on the Demo App

WebShield ships with a **deliberately vulnerable Flask app** that exercises every module:

```bash
# Terminal 1 — run the vulnerable demo app
python3 demo/app.py
# → http://localhost:5000

# Terminal 2 — scan it
webshield scan http://localhost:5000 --output report.html --json results.json
```

**Demo scan results (verified):**
```
Score: 0/100  Grade: F  |  100+ findings  |  25+ CRITICAL  |  ~12s
🔴 CRITICAL  — SQL injection, SSTI RCE, OS command injection, JWT alg:none,
               heap dump exposed, PII data (SSN/CC/IBAN), .git exposed,
               default credentials (admin/admin), NoSQL auth bypass...
🟠 HIGH      — Reflected XSS, DOM XSS, IDOR, CORS, source maps, actuator/env,
               OpenAPI spec with unauth endpoints, websocket downgrade...
🟡 MEDIUM    — CSRF, GraphQL introspection, cache deception, HPP, evasion...
🔵 LOW       — Cookie flags, info disclosure, SameSite missing...
```

---

## 🔍 Usage

### Basic scan
```bash
webshield scan https://example.com
```

### Full scan — all reports
```bash
webshield scan https://example.com \
  --output report.html \
  --json results.json \
  --sarif results.sarif \
  --timeout 15
```

### Authenticated scanning
```bash
webshield scan https://example.com \
  --auth-cookie "session=abc123" \
  --auth-header "Authorization=Bearer eyJ..."
```

### Scan specific modules only
```bash
webshield scan https://example.com \
  --modules sql_injection,xss_detection,default_credentials,cve_checks
```

### CI/CD mode — fail build on findings
```bash
webshield scan https://example.com --ci --fail-on high
echo $?   # 0 = pass, 1 = HIGH+ findings found
```

### Compare two scans (track improvements)
```bash
webshield scan https://example.com --json before.json
# ... deploy your fixes ...
webshield scan https://example.com --json after.json
webshield compare before.json after.json
```

### List all 60 modules
```bash
webshield list-modules
```

---

## 📦 Installation

```bash
# From source (recommended)
git clone https://github.com/AKIB473/webshield.git
cd webshield && pip install -e .

# Directly from GitHub
pip install git+https://github.com/AKIB473/webshield.git

# Development (tests included)
pip install -e ".[dev]"
```

**Requirements:** Python 3.9+ · No external tools needed

---

## 🆚 Why WebShield vs the alternatives?

| Feature | WebShield | Nikto | OWASP ZAP | Others |
|---|:---:|:---:|:---:|:---:|
| Security Score (0–100) | ✅ | ❌ | ❌ | ❌ |
| Letter Grade (A+ to F) | ✅ | ❌ | ❌ | ❌ |
| Code-level fix examples | ✅ | ❌ | ❌ | ❌ |
| Auto URL crawler | ✅ | ❌ | ✅ | ❌ |
| Default credential testing | ✅ | ❌ | ❌ | ❌ |
| WAF evasion techniques | ✅ | ✅ | ❌ | ❌ |
| OpenAPI spec import + testing | ✅ | ❌ | ✅ | ❌ |
| Source code disclosure (.git) | ✅ | ✅ | ✅ | ❌ |
| 403 bypass detection | ✅ | ❌ | ✅ | ❌ |
| PII detection (SSN, CC, IBAN) | ✅ | ❌ | ✅ | ❌ |
| Spring Actuator exposure | ✅ | ❌ | ✅ | ❌ |
| HTTP parameter pollution | ✅ | ❌ | ✅ | ❌ |
| CVE fingerprinting (10+ CVEs) | ✅ | ✅ | ✅ | ❌ |
| WebSocket security | ✅ | ❌ | ✅ | ❌ |
| SSTI → RCE detection | ✅ | ❌ | ❌ | ❌ |
| DOM XSS (JS static analysis) | ✅ | ❌ | ❌ | ❌ |
| Web cache deception | ✅ | ❌ | ❌ | ❌ |
| Business logic flaws | ✅ | ❌ | ❌ | ❌ |
| NoSQL injection | ✅ | ❌ | ❌ | ❌ |
| Insecure deserialization | ✅ | ❌ | ❌ | ❌ |
| JWT deep analysis | ✅ | ❌ | ❌ | ❌ |
| Supply chain CVE check | ✅ | ❌ | ❌ | ❌ |
| IDOR / Broken Access Control | ✅ | ❌ | Partial | ❌ |
| 2025 secret patterns | ✅ | ❌ | ❌ | ❌ |
| Authenticated scanning | ✅ | ❌ | ✅ | ❌ |
| SARIF (GitHub Security tab) | ✅ | ❌ | ❌ | ❌ |
| Async parallel scanning | ✅ | ❌ | ❌ | ❌ |
| Dark mode HTML report | ✅ | ❌ | ❌ | ❌ |
| Single `pip install` | ✅ | ❌ | ❌ | ❌ |

---

## 🧩 All 60 Modules

### 💉 Injection (OWASP A05)
| Module | What it detects | Max CVSS |
|---|---|:---:|
| `sql_injection` | Error-based, boolean-blind, time-based, UNION — MySQL/PG/MSSQL/Oracle/SQLite | 9.8 |
| `xss_detection` | Reflected XSS — 30+ payloads, WAF bypass, context-aware | 8.2 |
| `ssti` | SSTI → RCE — Jinja2, Twig, Freemarker, Velocity, Mako, ERB | 9.8 |
| `cmd_injection` | OS command injection — error-based + time-based blind | 9.8 |
| `lfi` | LFI/Path Traversal — 31 payloads: PHP wrappers, null bytes, `/proc/self` | 9.8 |
| `ssrf` | SSRF — AWS/GCP/Azure metadata, localhost bypass, IPv6 | 9.8 |
| `xxe` | XXE — XML external entity injection | 9.8 |
| `xxe_oob` | Blind/OOB XXE — error-based, parameter entities, JSON-to-XML | 9.8 |
| `nosql_injection` | NoSQL injection — MongoDB `$ne`/`$regex`/`$where` auth bypass | 9.1 |
| `log4shell` | Log4Shell (CVE-2021-44228), Shellshock, critical CVE detection | 10.0 |
| `proto_pollution` | JavaScript prototype pollution via URL parameters | 6.5 |
| `crlf_injection` | CRLF / HTTP response splitting | 6.1 |
| `evasion_scan` | WAF bypass — double-encoding, comment injection, case variation, HPP, null bytes | 9.8 |

### 🔓 Broken Access Control (OWASP A01)
| Module | What it detects | Max CVSS |
|---|---|:---:|
| `idor_check` | IDOR — sequential IDs, query param enumeration, unauth user lists | 9.1 |
| `business_logic` | Username enumeration, mass assignment, workflow bypass | 8.8 |
| `auth_hardening` | No rate limiting, MFA absence, default credentials, weak password reset | 9.8 |
| `http_header_injection` | Host header poisoning, X-Original-URL bypass | 8.1 |
| `bypass_403` | HTTP verb tampering, URL path tricks, X-Original-URL/X-Rewrite-URL bypass | 7.5 |

### 🔑 Authentication & Tokens (OWASP A07)
| Module | What it detects | Max CVSS |
|---|---|:---:|
| `jwt` | `alg:none`, weak secret brute-force, kid SQLi/path-traversal, missing exp | 9.8 |
| `cookies` | Missing Secure/HttpOnly/SameSite, low-entropy session IDs | 7.5 |
| `csrf_check` | Missing CSRF tokens, SameSite enforcement, state-changing GET | 6.5 |
| `rate_limit` | Brute-force protection, login throttling | 7.5 |
| `default_credentials` | 60+ apps — Jenkins, Grafana, WordPress, Portainer, Gitea, Kibana, phpMyAdmin, Tomcat, Drupal, Rancher, Traefik | 9.8 |

### 🧱 Security Headers & Config (OWASP A02/A05)
| Module | What it detects | Max CVSS |
|---|---|:---:|
| `headers` | HSTS, CSP, X-Frame-Options, X-Content-Type-Options + info-leaking headers | 7.5 |
| `csp` | Full CSP analysis — `unsafe-inline`, `unsafe-eval`, wildcards | 6.1 |
| `clickjacking` | X-Frame-Options, CSP `frame-ancestors` | 6.1 |
| `cors` | Wildcard, reflected origin + credentials, null origin, pre-domain bypass | 9.3 |
| `ssl_tls` | Certificate validity, TLS version, weak ciphers, self-signed | 9.8 |
| `http_methods` | Dangerous methods: PUT, DELETE, TRACE, CONNECT | 5.3 |
| `sri_check` | Missing `integrity=` on CDN scripts/styles | 6.1 |
| `mixed_content` | HTTP resources on HTTPS pages | 4.3 |
| `http_parameter_pollution` | Duplicate params, array notation, WAF bypass, business logic abuse | 7.5 |

### 🔍 Information Disclosure
| Module | What it detects | Max CVSS |
|---|---|:---:|
| `secret_leak` | API keys in source — AWS, GitHub, OpenAI, Anthropic, Stripe, Slack + more | 9.8 |
| `info_leak` | `.env`, `.git`, SQL dumps, backups — 24 sensitive paths | 9.8 |
| `source_code_disclosure` | `.git`/`.svn`/`.hg` repos, backup files (`.bak`, `.php~`), source maps, `composer.json` | 9.8 |
| `pii_detection` | SSN, credit cards (Luhn-verified), bulk email dumps, IBAN, UK National Insurance | 9.8 |
| `sensitive_paths` | Admin panels, phpMyAdmin, Spring Actuator, debug UIs — 36 paths | 5.3 |
| `dir_listing` | Directory listing — 40 paths including backups, logs, config | 6.5 |
| `tech_fingerprint` | 25 tech patterns + 13 CVE version checks | varies |
| `cloud_exposure` | AWS/GCP/Azure metadata endpoint exposure, S3 buckets | 7.5 |
| `malware_indicators` | Suspicious scripts, iframes, known malware patterns | 9.8 |
| `api_exposure` | Swagger/OpenAPI specs, GraphiQL IDE, admin APIs, Prometheus metrics | 7.5 |
| `spring_actuator` | `/actuator/heapdump`, `/actuator/env`, `/actuator/shutdown` + Quarkus, Laravel Telescope, Django debug | 9.8 |
| `exposed_panels` | 30 panels — Elasticsearch, Prometheus, Grafana, Mongo Express, HAProxy, Nginx/Apache status, .env | 9.8 |
| `openapi_scan` | OpenAPI/Swagger spec discovery → tests every endpoint for unauth access, sensitive data, SQLi | 9.8 |

### 🌐 Network & Infrastructure
| Module | What it detects | Max CVSS |
|---|---|:---:|
| `dns_email` | SPF, DMARC, CAA records — email spoofing protection | 5.3 |
| `subdomain_takeover` | CNAME → unclaimed services (GitHub Pages, Heroku, S3, Netlify…) | 8.1 |
| `waf_detect` | 15+ WAF signatures (Cloudflare, AWS, Akamai, ModSecurity, Sucuri…) | — |
| `open_redirect` | 22 redirect parameter names tested | 6.1 |
| `request_smuggling` | CL.TE and TE.CL via raw socket timing | 8.1 |
| `broken_links` | Dead links and unreachable resources | — |
| `security_txt` | RFC 9116 security.txt compliance | — |
| `websocket_security` | CSWSH, `ws://` downgrade on HTTPS, Next.js HMR in prod | 8.1 |
| `cve_checks` | Text4Shell, Confluence OGNL, Exchange ProxyShell, Grafana path traversal, Drupalgeddon2, Apache Struts, Fortinet auth bypass, GitLab, VMware vCenter, Citrix Bleed | 9.8 |

### 🧰 Supply Chain (OWASP A03/A06)
| Module | What it detects | Max CVSS |
|---|---|:---:|
| `supply_chain` | CVE check for `package.json`/`requirements.txt` — 30+ vulnerable packages | 9.8 |
| `graphql` | Introspection, batch DoS, depth DoS, alias flooding, GET-based CSRF | 7.5 |

### 🆕 Advanced Attack Surface
| Module | What it detects | Max CVSS |
|---|---|:---:|
| `web_cache_deception` | Omer Gil attack + James Kettle cache poisoning (unkeyed headers) | 9.0 |
| `file_upload` | Webshell detection, SVG-stored-XSS, dangerous MIME types | 9.8 |
| `dom_xss` | DOM XSS via JS static analysis — `location.hash→innerHTML`, jQuery source→sink | 8.8 |
| `insecure_deserialization` | Java serialization magic bytes, PHP serialize cookies, .NET ViewState | 9.8 |

---

## 🎯 Real-World Testing

Scanned against **ginandjuice.shop** (PortSwigger's intentionally vulnerable shop):

```
Score: 0/100  F  |  21 findings  |  23s

🟠 HIGH
  ✅ X-Original-URL bypasses /admin (403 → 200)
  ✅ Public AWS S3 bucket enumerable
  ✅ IDOR via ?id= query parameters
  ✅ No rate limiting on /login
  ✅ Missing HSTS, CSP

🟡 MEDIUM
  ✅ Web cache deception on /my-account
  ✅ CORS misconfiguration
  ✅ OpenAPI spec exposed
```

---

## 📊 Terminal Output

```
🛡️  WebShield v1.7.0 scanning https://example.com

🔍 Crawling for injectable parameters...
🔍 Found 8 URL(s) with parameters — running injection modules

╭──────────────────────────────── Scan Summary ─────────────────────────────╮
│  Target:  https://example.com                                             │
│  Score:   12/100  █████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░            │
│  Grade:     F                                                             │
│  Time:    11.2s  |  Modules: 78  |  Findings: 44                         │
╰───────────────────────────────────────────────────────────────────────────╯

🔴 CRITICAL (6)
  ■ Default Credentials Accepted — Jenkins (admin/admin)
    CVSS: 9.8

  ■ Git Repository Exposed (/.git/HEAD)
    Entire source code downloadable via git clone
    CVSS: 9.8

  ■ PII Leaked: Social Security Numbers (5 found)
    CVSS: 9.8

  ■ Spring Boot Environment Exposed (/actuator/env)
    DB_PASSWORD, JWT_SECRET, AWS_ACCESS_KEY all in plaintext
    CVSS: 9.8

  ■ SQL Injection (WAF Bypass via comment injection) — param: id
    CVSS: 9.8

  ■ XXE — Local File Read (/etc/passwd)
    CVSS: 9.8
```

---

## 🔗 CI/CD Integration

### GitHub Actions
```yaml
name: WebShield Security Audit

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Run WebShield
        run: |
          pip install git+https://github.com/AKIB473/webshield.git
          webshield scan ${{ vars.SITE_URL }} \
            --ci --fail-on high \
            --json results.json \
            --output report.html \
            --sarif results.sarif

      - name: Upload to GitHub Security tab
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif

      - name: Upload Report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: webshield-report
          path: "results.json\nreport.html"
```

---

## 🐍 Python API

```python
from webshield.core.scanner import run_scan
from webshield.reporter.html_report import save_html
from webshield.reporter.sarif import save_sarif
import json

# Run full scan — auto-crawls for injectable URLs
result = run_scan("https://example.com", timeout=15)

print(f"Score: {result.score}/100  Grade: {result.grade}")
print(f"Critical: {len(result.by_severity('CRITICAL'))}")
print(f"Scan time: {result.scan_duration}s")

for f in result.findings:
    print(f"[{f.severity.value}] {f.title}")
    if f.code_fix:
        print(f"  Fix: {f.code_fix[:100]}")

# Export all report formats
save_html(result, "report.html")
save_sarif(result, "results.sarif")

with open("results.json", "w") as fp:
    json.dump(result.to_dict(), fp, indent=2)
```

---

## 📈 Changelog

### v1.8.0 (current)
- 🆕 **Default Credentials** — tests 60+ apps (Jenkins, Grafana, WordPress, Portainer, Gitea, Kibana, phpMyAdmin, Tomcat, Drupal, Rancher, Traefik)
- 🆕 **Exposed Panels** — 30 admin/monitoring panels (Elasticsearch, Prometheus, Grafana, Mongo Express, HAProxy, Nginx status, .env, pgAdmin...)
- 🆕 **WAF Evasion** — double-encoding, comment injection, case variation, null bytes, HPP bypass
- 🆕 **OpenAPI Scan** — discovers and tests all endpoints from Swagger/OpenAPI specs
- 🆕 **XXE OOB** — blind/OOB XXE with error-based fallback and parameter entity detection
- 📊 Module count: 55 → 60 | Tests: 64 → 96

### v1.6.0
- 🆕 **Source Code Disclosure** — `.git`/`.svn`/`.hg` repos, backup files, source maps, config files
- 🆕 **403 Bypass** — verb tampering, URL manipulation, `X-Original-URL`/`X-Rewrite-URL` header bypass
- 🆕 **PII Detection** — SSN, credit cards (Luhn-verified), bulk email dumps, IBAN, UK NI numbers
- 🆕 **Spring Actuator** — `/actuator/heapdump`, `/env`, `/shutdown` + Laravel Telescope, Quarkus dev, Django debug
- 🆕 **HTTP Parameter Pollution** — duplicate params, array notation, WAF bypass
- 🆕 **CVE Checks** — Text4Shell, Confluence, Exchange ProxyShell, Grafana, Drupalgeddon2, Struts, Fortinet, GitLab, VMware, Citrix Bleed
- 🆕 **WebSocket Security** — CSWSH origin bypass, `ws://` downgrade, Next.js HMR exposure
- 📊 Module count: 48 → 55

### v1.5.1
- 🆕 **URL Crawler** — auto-discovers injectable endpoints before running injection modules
- 🆕 **Demo App** (`demo/app.py`) — deliberately vulnerable Flask app, one vuln per module
- ✅ Verified: 23/23 key module coverage on demo app (88 findings, 23 CRITICAL)

### v1.5.0
- 🆕 SSTI, Web Cache Deception, File Upload Security, DOM XSS, Business Logic
- 📊 Module count: 43 → 48

### v1.4.0
- 🆕 OS Command Injection, NoSQL Injection, Host Header Injection, Insecure Deserialization
- 🆕 `--auth-cookie` / `--auth-header`, `webshield compare`
- 📊 Module count: 39 → 43

### v1.3.0
- 🆕 IDOR, API Exposure, Directory Listing, Auth Hardening
- 📊 Module count: 35 → 39 | Full OWASP Top 10:2025 coverage

### v1.2.0
- 🆕 SQLi, XSS, LFI, SSRF, XXE, Log4Shell, Secret Leak, CSRF, Cloud Exposure, Malware, Rate Limit, Broken Links, security.txt, CRLF, Proto Pollution
- ⚡ Async parallel scanning | 🆕 SARIF output
- 📊 Module count: 20 → 35

### v1.0.0
- 🎉 Initial release — 17 modules, SSL/TLS, headers, CORS, CSP, JWT, cookies, WAF, GraphQL, supply chain CVEs

---

## 🛡️ Ethical Use

WebShield is for **owners and authorized testers** of websites only.

- ✅ Your own sites
- ✅ Sites you have **written permission** to test
- ❌ Unauthorized scanning is illegal and unethical

---

## 📄 License

MIT — see [LICENSE](LICENSE)

**AKIBUZZAMAN AKIB** — [@AKIB473](https://github.com/AKIB473)

⭐ **If WebShield helped you, star it** — it helps others find it!
