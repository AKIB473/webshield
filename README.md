# 🛡️ WebShield

**Website Security Auditor — Know your site's security. Fix it today.**

[![PyPI version](https://img.shields.io/pypi/v/webshield?color=blue)](https://pypi.org/project/webshield/)
[![Python](https://img.shields.io/pypi/pyversions/webshield)](https://pypi.org/project/webshield/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![CI](https://github.com/AKIB473/webshield/actions/workflows/ci.yml/badge.svg)](https://github.com/AKIB473/webshield/actions)
[![Stars](https://img.shields.io/github/stars/AKIB473/webshield?style=social)](https://github.com/AKIB473/webshield)

WebShield is a **developer-first** web security scanner that gives you a clean **security score (0–100)**, **letter grade (A+ to F)**, and tells you **exactly how to fix every issue** with code examples — unlike traditional tools built for penetration testers.

> **v1.0.1** — Async parallel scanning (3× faster), 20 modules, SARIF output for GitHub Code Scanning, 3 new modules: Clickjacking, Mixed Content, SRI.

---

## ✨ Why WebShield?

| Feature | WebShield | Nikto | OWASP ZAP | Others |
|---|---|---|---|---|
| Security Score (0–100) | ✅ | ❌ | ❌ | ❌ |
| Letter Grade (A+ to F) | ✅ | ❌ | ❌ | ❌ |
| Code-level fix examples | ✅ | ❌ | ❌ | ❌ |
| JWT token analysis | ✅ | ❌ | ❌ | ❌ |
| Supply chain CVE check | ✅ | ❌ | ❌ | ❌ |
| GraphQL security | ✅ | ❌ | Partial | ❌ |
| SARIF (GitHub Scanning) | ✅ | ❌ | ❌ | ❌ |
| Async parallel scanning | ✅ | ❌ | ❌ | ❌ |
| Beautiful terminal UI | ✅ | ❌ | ❌ | ❌ |
| Single `pip install` | ✅ | ❌ | ❌ | ❌ |

---

## 🚀 Quick Start

```bash
pip install webshield
webshield scan https://yoursite.com
```

---

## 📦 Installation

```bash
# From PyPI
pip install webshield

# Latest from GitHub
pip install git+https://github.com/AKIB473/webshield.git

# Development
git clone https://github.com/AKIB473/webshield.git
cd webshield && pip install -e ".[dev]"
```

**Requirements:** Python 3.9+ · No external tools needed · Single pip install

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

## 🧩 Modules (v1.0.1 — 20 total)

| Module | What It Checks |
|---|---|
| `ssl_tls` | Certificate validity/expiry, TLS version, weak ciphers, self-signed |
| `headers` | 8 security headers + dangerous info-leaking headers (Server, X-Powered-By) |
| `cookies` | Secure, HttpOnly, SameSite flags, weak session IDs |
| `info_leak` | .env, .git, SQL dumps, backups — 24 sensitive paths |
| `sensitive_paths` | Admin panels, phpMyAdmin, Spring Actuator, debug UIs — 36 paths |
| `cors` | Wildcard origins, reflected origins with credentials, null origin |
| `csp` | Full CSP directive analysis, unsafe-inline, unsafe-eval, wildcards |
| `dns_email` | SPF, DMARC, CAA records — email spoofing protection |
| `waf_detect` | 15+ WAF signatures (Cloudflare, AWS, Akamai, ModSec, Sucuri...) |
| `tech_fingerprint` | 25 tech patterns + 13 CVE version checks |
| `open_redirect` | 22 redirect parameter names tested |
| `http_methods` | Dangerous methods: PUT, DELETE, TRACE, CONNECT |
| `jwt` | alg:none bypass, weak secret brute-force, missing expiry, sensitive payload |
| `subdomain_takeover` | CNAME → 14 unclaimed services (GitHub Pages, Heroku, S3, Netlify...) |
| `graphql` | Introspection, batch query DoS, depth DoS, GET-based CSRF |
| `request_smuggling` | CL.TE and TE.CL timing-based detection via raw sockets |
| `supply_chain` | CVE check for package.json / requirements.txt — 19 vulnerable packages |
| `clickjacking` | X-Frame-Options, CSP frame-ancestors, ALLOWALL detection *(v1.0.1)* |
| `mixed_content` | HTTP resources on HTTPS pages (active & passive) *(v1.0.1)* |
| `sri_check` | Missing integrity= on CDN scripts/styles *(v1.0.1)* |

---

## 📊 Example Terminal Output

```
🛡️  WebShield v1.0.1 scanning https://example.com

╭──────────────────────────── Scan Summary ─────────────────────────────╮
│  Target:  https://example.com                                         │
│  Score:   45/100  ██████████████████░░░░░░░░░░░░░░░░░░░░              │
│  Grade:     D                                                         │
│  Time:    3.1s  |  Modules: 20  |  Findings: 18                       │
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

# Run full scan
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

### v1.0.1
- ⚡ **Async parallel scanning** — all modules run concurrently (~3× faster)
- 🆕 **SARIF output** — GitHub Code Scanning integration (`--sarif results.sarif`)
- 🆕 **Clickjacking module** — X-Frame-Options, CSP frame-ancestors, ALLOWALL detection
- 🆕 **Mixed Content module** — active & passive HTTP resources on HTTPS pages
- 🆕 **SRI Check module** — missing `integrity=` on CDN scripts/styles
- 🔧 WAF detection false positive fix for standard nginx servers
- 📊 Time elapsed shown in progress bar

### v1.0.0
- Initial release with 17 scan modules

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
