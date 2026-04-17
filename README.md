# 🛡️ WebShield

**Website Security Auditor — Know your site's security. Fix it today.**

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![CI](https://github.com/AKIB473/webshield/actions/workflows/ci.yml/badge.svg)](https://github.com/AKIB473/webshield/actions)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![Stars](https://img.shields.io/github/stars/AKIB473/webshield?style=social)](https://github.com/AKIB473/webshield)

WebShield is a **developer-first** web security scanner that gives you a clean **security score (0–100)**, **letter grade (A+ to F)**, and tells you **exactly how to fix every issue** with code examples — unlike traditional tools built for penetration testers.

> **v1.3.0** — 39 scan modules covering OWASP Top 10:2025. New: IDOR/Broken Access Control detection, API endpoint exposure, directory listing, and deep authentication hardening (MFA, rate limiting, default credentials, password reset flaws).

---

## ✨ Why WebShield?

| Feature | WebShield | Nikto | OWASP ZAP | Others |
|---|---|---|---|---|
| Security Score (0–100) | ✅ | ❌ | ❌ | ❌ |
| Letter Grade (A+ to F) | ✅ | ❌ | ❌ | ❌ |
| Code-level fix examples | ✅ | ❌ | ❌ | ❌ |
| SQL Injection detection | ✅ | Partial | ✅ | Partial |
| XSS detection | ✅ | Partial | ✅ | Partial |
| JWT token analysis | ✅ | ❌ | ❌ | ❌ |
| Supply chain CVE check | ✅ | ❌ | ❌ | ❌ |
| IDOR / Broken Access Control | ✅ | ❌ | Partial | ❌ |
| API exposure detection | ✅ | ❌ | ❌ | ❌ |
| GraphQL security | ✅ | ❌ | Partial | ❌ |
| Log4Shell detection | ✅ | ❌ | ❌ | ❌ |
| Secret leak detection | ✅ | ❌ | ❌ | ❌ |
| SARIF (GitHub Scanning) | ✅ | ❌ | ❌ | ❌ |
| Async parallel scanning | ✅ | ❌ | ❌ | ❌ |
| Beautiful terminal UI | ✅ | ❌ | ❌ | ❌ |
| Single `pip install` | ✅ | ❌ | ❌ | ❌ |

---

## 🚀 Quick Start

```bash
git clone https://github.com/AKIB473/webshield.git
cd webshield
pip install -e .
webshield scan https://yoursite.com
```

---

## 📦 Installation

```bash
# Clone and install
git clone https://github.com/AKIB473/webshield.git
cd webshield
pip install -e .

# Install directly from GitHub
pip install git+https://github.com/AKIB473/webshield.git

# Development (with test dependencies)
git clone https://github.com/AKIB473/webshield.git
cd webshield && pip install -e ".[dev]"
```

**Requirements:** Python 3.9+ · No external tools needed

---

## 🔍 Usage

### Basic Scan
```bash
webshield scan https://example.com
```

### Full Scan with All Reports
```bash
webshield scan https://example.com \
  --output report.html \
  --json results.json \
  --sarif results.sarif
```

### Scan Specific Modules Only
```bash
webshield scan https://example.com --modules ssl_tls,headers,cors,csp,jwt
```

### CI/CD — Fail Build on High+ Findings
```bash
webshield scan https://example.com --ci --fail-on high
echo $?  # 0 = pass, 1 = fail
```

### Print JSON to stdout (for scripting)
```bash
webshield scan https://example.com --print-json | jq .summary
```

### List All Modules
```bash
webshield list-modules
```

---

## 🧩 Modules (v1.2.0 — 35 total)

### 🔐 Authentication & Tokens
| Module | What It Checks |
|---|---|
| `jwt` | alg:none bypass, weak secret brute-force, missing expiry, sensitive payload data |
| `cookies` | Secure, HttpOnly, SameSite flags, weak/predictable session IDs |
| `csrf_check` | CSRF token presence, SameSite cookie enforcement, state-changing GET endpoints |

### 🌐 Transport & Protocol
| Module | What It Checks |
|---|---|
| `ssl_tls` | Certificate validity/expiry, TLS version, weak ciphers, self-signed certs |
| `http_methods` | Dangerous methods: PUT, DELETE, TRACE, CONNECT |
| `request_smuggling` | CL.TE and TE.CL timing-based detection via raw sockets |
| `crlf_injection` | CRLF injection in headers via response splitting |
| `mixed_content` | HTTP resources on HTTPS pages (active & passive) |

### 🛡️ Security Headers & Policies
| Module | What It Checks |
|---|---|
| `headers` | 8 security headers + dangerous info-leaking headers (Server, X-Powered-By) |
| `csp` | Full CSP directive analysis, unsafe-inline, unsafe-eval, wildcards |
| `clickjacking` | X-Frame-Options, CSP frame-ancestors, ALLOWALL detection |
| `sri_check` | Missing `integrity=` attributes on CDN scripts/styles |
| `security_txt` | Presence and validity of `/.well-known/security.txt` |

### 💉 Injection Attacks
| Module | What It Checks |
|---|---|
| `sql_injection` | Error-based and time-based blind SQLi in URL parameters |
| `xss_detection` | Reflected XSS via parameter injection and response analysis |
| `lfi` | Local File Inclusion via path traversal payloads |
| `ssrf` | Server-Side Request Forgery via redirect and parameter manipulation |
| `xxe` | XML External Entity injection in XML-accepting endpoints |
| `log4shell` | CVE-2021-44228 Log4Shell JNDI injection detection |
| `proto_pollution` | JavaScript prototype pollution via query parameters |

### 🔍 Information Disclosure
| Module | What It Checks |
|---|---|
| `info_leak` | .env, .git, SQL dumps, backups — 24 sensitive paths |
| `sensitive_paths` | Admin panels, phpMyAdmin, Spring Actuator, debug UIs — 36 paths |
| `secret_leak` | API keys, tokens, and credentials exposed in page source |
| `tech_fingerprint` | 25 tech patterns + 13 CVE version checks |
| `cloud_exposure` | Exposed cloud metadata endpoints (AWS, GCP, Azure) |
| `malware_indicators` | Suspicious scripts, iframes, and known malware patterns |

### 🌍 Network & Infrastructure
| Module | What It Checks |
|---|---|
| `cors` | Wildcard origins, reflected origins with credentials, null origin |
| `dns_email` | SPF, DMARC, CAA records — email spoofing protection |
| `waf_detect` | 15+ WAF signatures (Cloudflare, AWS, Akamai, ModSec, Sucuri...) |
| `subdomain_takeover` | CNAME → 14 unclaimed services (GitHub Pages, Heroku, S3, Netlify...) |
| `open_redirect` | 22 redirect parameter names tested |
| `rate_limit` | Rate limiting and brute-force protection detection |
| `broken_links` | Dead links and unreachable resources on the target page |

### 🔑 Access Control (OWASP A01:2025 — #1 Real-World Risk)
| Module | What It Checks |
|---|---|
| `idor_check` | IDOR via sequential IDs, query params, unauthenticated user list endpoints |
| `api_exposure` | Exposed Swagger/OpenAPI specs, GraphiQL IDE, admin APIs, internal endpoints |
| `dir_listing` | Directory listing on 40 paths — detects backup, log, config dir exposure |
| `auth_hardening` | Rate limiting, MFA/2FA signals, default credentials, password reset security |

### 🧰 Supply Chain & Dependencies
| Module | What It Checks |
|---|---|
| `supply_chain` | CVE check for package.json / requirements.txt — 19 vulnerable packages |
| `graphql` | Introspection, batch query DoS, depth DoS, GET-based CSRF |

---

## 📊 Example Terminal Output

```
🛡️  WebShield v1.2.0 scanning https://example.com

╭──────────────────────────── Scan Summary ─────────────────────────────╮
│  Target:  https://example.com                                         │
│  Score:   45/100  ██████████████████░░░░░░░░░░░░░░░░░░░░              │
│  Grade:     D                                                         │
│  Time:    3.1s  |  Modules: 39  |  Findings: 18                       │
╰───────────────────────────────────────────────────────────────────────╯

🔴 CRITICAL (1)
  ■ Exposed .env File
    The .env file is publicly accessible. Contains DB passwords and API keys.
    Evidence: HTTP 200 at https://example.com/.env — 412 bytes
    Fix: location ~ /\.env { deny all; return 404; }
    CVSS: 9.8

🟠 HIGH (3)
  ■ Missing Security Header: Strict-Transport-Security
  ...
```

---

## 🔗 CI/CD Integration

### GitHub Actions (with SARIF upload)
```yaml
name: WebShield Security Audit

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run WebShield
        run: |
          pip install webshield
          webshield scan ${{ vars.SITE_URL }} \
            --ci --fail-on high \
            --json results.json \
            --sarif results.sarif \
            --output report.html

      - name: Upload SARIF to GitHub Security tab
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif

      - name: Upload HTML Report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: webshield-report
          path: |
            results.json
            report.html
```

---

## 🐍 Python API

```python
from webshield.core.scanner import run_scan
from webshield.reporter.html_report import save_html
from webshield.reporter.sarif import save_sarif

# Run full scan (async parallel — all 35 modules run concurrently)
result = run_scan("https://example.com")

print(f"Score: {result.score}/100  Grade: {result.grade}")
print(f"Critical: {len(result.by_severity('CRITICAL'))}")

for f in result.findings:
    print(f"[{f.severity.value}] {f.title}")
    if f.remediation:
        print(f"  Fix: {f.remediation}")

# Export reports
save_html(result, "report.html")
save_sarif(result, "results.sarif")

import json
with open("results.json", "w") as fp:
    json.dump(result.to_dict(), fp, indent=2)
```

---

## 📈 Changelog

### v1.3.0
- 🆕 **IDOR / Broken Access Control module** — sequential ID enumeration, unauthenticated user lists, query param IDOR (OWASP A01:2025 — #1 exploited class)
- 🆕 **API Exposure module** — detects Swagger/OpenAPI specs, GraphiQL IDE, admin APIs, internal endpoints, Prometheus metrics
- 🆕 **Directory Listing module** — probes 40 paths including backup, log, config, and node_modules dirs
- 🆕 **Auth Hardening module** — tests rate limiting, MFA presence, default credentials, password reset security
- 📊 Module count: 35 → 39
- 📌 Full OWASP Top 10:2025 coverage

### v1.2.0
- 🆕 **SQL Injection module** — error-based and time-based blind SQLi detection
- 🆕 **XSS detection module** — reflected XSS via parameter injection
- 🆕 **LFI module** — local file inclusion via path traversal payloads
- 🆕 **SSRF module** — server-side request forgery detection
- 🆕 **XXE module** — XML external entity injection
- 🆕 **Log4Shell module** — CVE-2021-44228 JNDI injection detection
- 🆕 **Secret leak module** — API keys and credentials in page source
- 🆕 **CSRF check module** — token presence and SameSite enforcement
- 🆕 **Cloud exposure module** — AWS/GCP/Azure metadata endpoint detection
- 🆕 **Malware indicators module** — suspicious scripts and iframe detection
- 🆕 **Rate limit module** — brute-force protection detection
- 🆕 **Broken links module** — dead link detection
- 🆕 **Security.txt module** — RFC 9116 compliance check
- 🆕 **CRLF injection module** — response splitting detection
- 🆕 **Proto pollution module** — JavaScript prototype pollution
- 📊 Module count: 20 → 35

### v1.0.1
- ⚡ **Async parallel scanning** — all modules run concurrently (~3× faster)
- 🆕 **SARIF output** — GitHub Code Scanning integration (`--sarif results.sarif`)
- 🆕 **Clickjacking module** — X-Frame-Options, CSP frame-ancestors, ALLOWALL detection
- 🆕 **Mixed Content module** — active & passive HTTP resources on HTTPS pages
- 🆕 **SRI Check module** — missing `integrity=` on CDN scripts/styles
- 🔧 WAF detection false positive fix for standard nginx servers
- 📊 Time elapsed shown in progress bar

### v1.0.0
- 🎉 Initial release with 17 scan modules

---

## 🛠️ Ethical Use

WebShield is for **owners and authorized testers** of websites only.

- ✅ Your own sites
- ✅ Sites you have written permission to test
- ❌ Unauthorized scanning is illegal

---

## 📄 License

MIT — see [LICENSE](LICENSE)

---

## 👤 Author

**AKIBUZZAMAN AKIB** — [@AKIB473](https://github.com/AKIB473)

---

⭐ **If WebShield helped you, please star it** — it helps others find it!
