# 🛡️ WebShield

**Website Security Auditor — Know your site's security. Fix it today.**

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![CI](https://github.com/AKIB473/webshield/actions/workflows/ci.yml/badge.svg)](https://github.com/AKIB473/webshield/actions)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![Version](https://img.shields.io/badge/version-1.5.1-brightgreen)](https://github.com/AKIB473/webshield)
[![Stars](https://img.shields.io/github/stars/AKIB473/webshield?style=social)](https://github.com/AKIB473/webshield)

WebShield is a **developer-first** web security scanner. Point it at any website and get:
- A **security score (0–100)** and **letter grade (A+ to F)**
- **48 parallel scan modules** covering every OWASP Top 10:2025 category
- **Code-level fix examples** for every finding — not just "you have XSS", but *here's the exact vulnerable line and the safe version*
- **Auto-crawling** — discovers injectable URLs automatically, no manual param setup
- **HTML + JSON + SARIF** reports

> **v1.5.1** — 48 modules, URL crawler, 5 new deep-attack modules (SSTI→RCE, Cache Deception, DOM XSS, File Upload, Business Logic), authenticated scanning, `compare` command. Tested against a deliberately vulnerable demo app — **23 CRITICAL findings detected including SQL injection, SSTI RCE, OS command injection, JWT alg:none, NoSQL auth bypass, deserialization, and more.**

---

## ⚡ Quick Start

```bash
git clone https://github.com/AKIB473/webshield.git
cd webshield
pip install -e .
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
Score: 0/100  Grade: F  |  88 findings  |  23 CRITICAL  |  9.8s
🔴 CRITICAL  23  — SQL injection, SSTI RCE, OS command injection, JWT alg:none, ...
🟠 HIGH      23  — Reflected XSS, DOM XSS, IDOR, CORS, missing headers, ...
🟡 MEDIUM    22  — CSRF, GraphQL introspection, cache deception, admin panel, ...
🔵 LOW       11  — Cookie flags, info disclosure, SameSite missing, ...
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

### Authenticated scanning (cookies or headers)
```bash
# Pass session cookie for authenticated areas
webshield scan https://example.com \
  --auth-cookie "session=abc123" \
  --auth-cookie "csrftoken=xyz"

# Pass Bearer token
webshield scan https://example.com \
  --auth-header "Authorization=Bearer eyJ..."
```

### Scan specific modules only
```bash
webshield scan https://example.com --modules sql_injection,xss_detection,ssti,cors,jwt
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

### List all 48 modules
```bash
webshield list-modules
```

### Print JSON to stdout (scripting)
```bash
webshield scan https://example.com --print-json | jq .summary
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
| SSTI → RCE detection | ✅ | ❌ | ❌ | ❌ |
| DOM XSS (JS static analysis) | ✅ | ❌ | ❌ | ❌ |
| Web cache deception | ✅ | ❌ | ❌ | ❌ |
| Business logic flaws | ✅ | ❌ | ❌ | ❌ |
| NoSQL injection | ✅ | ❌ | ❌ | ❌ |
| Insecure deserialization | ✅ | ❌ | ❌ | ❌ |
| JWT deep analysis | ✅ | ❌ | ❌ | ❌ |
| Supply chain CVE check | ✅ | ❌ | ❌ | ❌ |
| IDOR / Broken Access Control | ✅ | ❌ | Partial | ❌ |
| 2025 secret patterns (OpenAI, Anthropic, HF) | ✅ | ❌ | ❌ | ❌ |
| Authenticated scanning | ✅ | ❌ | ✅ | ❌ |
| SARIF (GitHub Security tab) | ✅ | ❌ | ❌ | ❌ |
| Async parallel scanning | ✅ | ❌ | ❌ | ❌ |
| Dark mode HTML report | ✅ | ❌ | ❌ | ❌ |
| Single `pip install` | ✅ | ❌ | ❌ | ❌ |

---

## 🧩 All 48 Modules

### 💉 Injection (OWASP A05)
| Module | What it detects | Max CVSS |
|---|---|:---:|
| `sql_injection` | Error-based, boolean-blind, time-based, UNION — MySQL/PG/MSSQL/Oracle/SQLite | 9.8 |
| `xss_detection` | Reflected XSS — 30+ payloads, WAF bypass, context-aware (JS/HTML/attr) | 8.2 |
| `ssti` | **SSTI → RCE** — Jinja2, Twig, Freemarker, Velocity, Mako, ERB (14 probes + RCE confirm) | 9.8 |
| `cmd_injection` | OS command injection — error-based + time-based blind (Unix/Windows) | 9.8 |
| `lfi` | LFI/Path Traversal — 31 payloads: PHP wrappers, null bytes, `/proc/self`, logs | 9.8 |
| `ssrf` | SSRF — AWS/GCP/Azure metadata, localhost bypass, IPv6, decimal IP | 9.8 |
| `xxe` | XXE — XML external entity injection | 9.8 |
| `nosql_injection` | NoSQL injection — MongoDB `$ne`/`$regex`/`$where` auth bypass | 9.1 |
| `log4shell` | Log4Shell (CVE-2021-44228), Shellshock, critical CVE detection | 10.0 |
| `proto_pollution` | JavaScript prototype pollution via URL parameters | 6.5 |
| `crlf_injection` | CRLF / HTTP response splitting | 6.1 |

### 🔓 Broken Access Control (OWASP A01 — #1 Risk)
| Module | What it detects | Max CVSS |
|---|---|:---:|
| `idor_check` | IDOR — sequential IDs, query param enumeration, unauth user lists | 9.1 |
| `business_logic` | Username enumeration, mass assignment (`is_admin`), workflow bypass | 8.8 |
| `auth_hardening` | No rate limiting, MFA absence, default credentials, weak password reset | 9.8 |
| `http_header_injection` | Host header poisoning, X-Original-URL bypass, routing tricks | 8.1 |

### 🔑 Authentication & Tokens (OWASP A07)
| Module | What it detects | Max CVSS |
|---|---|:---:|
| `jwt` | `alg:none`, weak secret brute-force, kid SQLi/path-traversal, jku injection, missing exp | 9.8 |
| `cookies` | Missing Secure/HttpOnly/SameSite, low-entropy session IDs, broad domain scope | 7.5 |
| `csrf_check` | Missing CSRF tokens, SameSite enforcement, state-changing GET | 6.5 |
| `rate_limit` | Brute-force protection, login throttling | 7.5 |

### 🧱 Security Headers & Config (OWASP A02/A05)
| Module | What it detects | Max CVSS |
|---|---|:---:|
| `headers` | HSTS, CSP, X-Frame-Options, X-Content-Type-Options + info-leaking headers | 7.5 |
| `csp` | Full CSP analysis — `unsafe-inline`, `unsafe-eval`, wildcards, missing directives | 6.1 |
| `clickjacking` | X-Frame-Options, CSP `frame-ancestors` | 6.1 |
| `cors` | Wildcard, reflected origin + credentials, null origin, pre-domain bypass | 9.3 |
| `ssl_tls` | Certificate validity, TLS version, weak ciphers, self-signed | 9.8 |
| `http_methods` | Dangerous methods: PUT, DELETE, TRACE, CONNECT | 5.3 |
| `sri_check` | Missing `integrity=` on CDN scripts/styles | 6.1 |
| `mixed_content` | HTTP resources on HTTPS pages | 4.3 |

### 🔍 Information Disclosure
| Module | What it detects | Max CVSS |
|---|---|:---:|
| `secret_leak` | API keys in source — AWS, GitHub, OpenAI, Anthropic, HuggingFace, Stripe, Slack, Telegram, Discord + more | 9.8 |
| `info_leak` | `.env`, `.git`, SQL dumps, backups — 24 sensitive paths | 9.8 |
| `sensitive_paths` | Admin panels, phpMyAdmin, Spring Actuator, debug UIs — 36 paths | 5.3 |
| `dir_listing` | Directory listing — 40 paths including backups, logs, config | 6.5 |
| `tech_fingerprint` | 25 tech patterns + 13 CVE version checks | varies |
| `cloud_exposure` | AWS/GCP/Azure metadata endpoint exposure, S3 buckets | 7.5 |
| `malware_indicators` | Suspicious scripts, iframes, known malware patterns | 9.8 |
| `api_exposure` | Swagger/OpenAPI specs, GraphiQL IDE, admin APIs, Prometheus metrics | 7.5 |

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

### 🧰 Supply Chain (OWASP A03/A06)
| Module | What it detects | Max CVSS |
|---|---|:---:|
| `supply_chain` | CVE check for `package.json`/`requirements.txt` — 30+ vulnerable packages including 2024–2025 CVEs | 9.8 |
| `graphql` | Introspection, batch DoS, depth DoS, alias flooding, GET-based CSRF | 7.5 |

### 🆕 Advanced Attack Surface (v1.4.0–v1.5.0)
| Module | What it detects | Max CVSS |
|---|---|:---:|
| `web_cache_deception` | **Omer Gil web cache deception** (private data cacheable) + **James Kettle cache poisoning** (unkeyed headers) | 9.0 |
| `file_upload` | Webshell detection, SVG-stored-XSS, dangerous MIME types, missing nosniff | 9.8 |
| `dom_xss` | DOM XSS via JS static analysis — `location.hash→innerHTML`, `eval(url)`, jQuery source→sink, postMessage | 8.8 |
| `insecure_deserialization` | Java serialization magic bytes in cookies, PHP serialize, unprotected .NET ViewState | 9.8 |

---

## 🎯 Real-World Testing Results

Scanned against **ginandjuice.shop** (PortSwigger's intentionally vulnerable shop):

```
Score: 0/100  F  |  21 findings  |  23s

🟠 HIGH
  ✅ X-Original-URL header bypasses /admin (403 → 200)
  ✅ Public AWS S3 bucket enumerable
  ✅ IDOR via ?id= query parameters
  ✅ No rate limiting on /login (8 probes, no lockout)
  ✅ Missing HSTS, CSP

🟡 MEDIUM
  ✅ Web cache deception on /my-account (99% content similarity)
  ✅ CORS misconfiguration
```

---

## 📊 Terminal Output

```
🛡️  WebShield v1.5.1 scanning https://example.com

🔍 Crawling for injectable parameters...
🔍 Found 8 URL(s) with parameters — running injection modules

╭──────────────────────────────── Scan Summary ─────────────────────────────╮
│  Target:  https://example.com                                             │
│  Score:   32/100  █████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░             │
│  Grade:     F                                                             │
│  Time:    9.8s  |  Modules: 48  |  Findings: 31                          │
╰───────────────────────────────────────────────────────────────────────────╯

🔴 CRITICAL (4)
  ■ SQL Injection (Error-Based) — MySQL | param: id
    Error-based SQLi confirmed on 'id'. Payload: 1' AND '1'='1'--
    Fix: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
    CVSS: 9.8

  ■ SSTI Detected (Jinja2) | param: msg
    Template evaluation confirmed: {{7*7}} → 49
    CVSS: 9.8

  ■ JWT Uses Algorithm 'none' — Signature Bypass
    alg:none token accepted. Any claims can be forged.
    CVSS: 9.8

  ■ Java Serialized Object in Cookie: 'JSESSIONID'
    Magic bytes 0xACED detected. Gadget chain RCE possible.
    CVSS: 9.8
```

---

## 🔗 CI/CD Integration

### GitHub Actions
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
          pip install git+https://github.com/AKIB473/webshield.git
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
save_html(result, "report.html")           # Beautiful dark/light mode HTML
save_sarif(result, "results.sarif")        # GitHub Code Scanning

with open("results.json", "w") as fp:
    json.dump(result.to_dict(), fp, indent=2)
```

---

## 📈 Changelog

### v1.5.1 (current)
- 🆕 **URL Crawler** — auto-discovers injectable endpoints before running injection modules
- 🆕 **Demo App** (`demo/app.py`) — deliberately vulnerable Flask app, one vuln per module
- 🔧 **Injection modules** now try all crawled URLs automatically (SQLi, XSS, SSTI, CMDi, LFI, SSRF…)
- 🔧 **cookies/jwt/csrf** modules probe known auth endpoints
- 🔧 **business_logic** — improved username enumeration detection
- 🔧 **dom_xss** — skips CDN/framework files, prevents false positives on React/Vue source
- ✅ Verified: 23/23 key module coverage on demo app (88 findings, 23 CRITICAL)

### v1.5.0
- 🆕 **SSTI** — Server-Side Template Injection with RCE confirmation (Jinja2, Twig, Freemarker, Velocity, Mako, ERB)
- 🆕 **Web Cache Deception** — Omer Gil attack + James Kettle cache poisoning via 7 unkeyed headers
- 🆕 **File Upload Security** — webshell detection, SVG-XSS, dangerous MIME types
- 🆕 **DOM XSS** — static JS analysis: `location.hash→innerHTML`, `eval(url)`, jQuery source→sink
- 🆕 **Business Logic** — username enumeration, mass assignment, forced browsing/workflow bypass
- 🔧 **LFI** upgraded: 10 → 31 payloads (PHP wrappers, `/proc/self`, null bytes, log poisoning)
- 📊 Module count: 43 → 48

### v1.4.1
- 🔧 Fixed UnicodeEncodeError in HTML report (surrogate chars from response bodies)
- 🔧 Fixed `cookies` module: `resp.url` is httpx URL object not string
- 🔧 Fixed Host header injection false positive (baseline comparison)
- 🔧 Fixed scan hanging forever on unreachable targets (45s hard per-module timeout)
- 🔧 Fixed version string showing v1.2.0 in terminal footer

### v1.4.0
- 🆕 **OS Command Injection** — error-based + time-based blind (Unix/Windows)
- 🆕 **NoSQL Injection** — MongoDB `$ne`/`$regex`/`$where` auth bypass + URL param injection
- 🆕 **Host Header Injection** — Host header poisoning, X-Forwarded-Host cache poisoning, routing bypass
- 🆕 **Insecure Deserialization** — Java serial magic bytes, PHP serialize cookies, .NET ViewState
- 🆕 **`--auth-cookie` / `--auth-header`** — authenticated scanning for protected pages
- 🆕 **`webshield compare`** — diff two JSON scan results, show fixed/new/remaining
- 🔧 Grade scale: D+ / D / D- (was just "D")
- 🔧 Score capped at 0 (never goes negative)
- 🔧 Secret patterns: OpenAI, Anthropic, HuggingFace, Cloudflare, DigitalOcean, Telegram, Discord
- 🔧 Supply chain: 2024–2025 CVEs (Next.js auth bypass, Werkzeug RCE, LangChain RCE…)
- 📊 Module count: 39 → 43

### v1.3.0
- 🆕 IDOR / Broken Access Control, API Exposure, Directory Listing, Auth Hardening
- 📊 Module count: 35 → 39 | Full OWASP Top 10:2025 coverage

### v1.2.0
- 🆕 SQLi, XSS, LFI, SSRF, XXE, Log4Shell, Secret Leak, CSRF, Cloud Exposure, Malware, Rate Limit, Broken Links, security.txt, CRLF, Proto Pollution
- ⚡ Async parallel scanning (~3× faster)
- 🆕 SARIF output for GitHub Code Scanning
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

---

## 👤 Author

**AKIBUZZAMAN AKIB** — [@AKIB473](https://github.com/AKIB473)

⭐ **If WebShield helped you, star it** — it helps others find it!
