# 🛡️ WebShield

**Website Security Auditor — Know your site's security. Fix it today.**

[![PyPI version](https://img.shields.io/pypi/v/webshield?color=blue)](https://pypi.org/project/webshield/)
[![Python](https://img.shields.io/pypi/pyversions/webshield)](https://pypi.org/project/webshield/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Stars](https://img.shields.io/github/stars/AKIB473/webshield?style=social)](https://github.com/AKIB473/webshield)

WebShield is a **developer-first** web security scanner that gives you a clean security score, letter grade, and **tells you exactly how to fix every issue it finds** — with code examples.

Unlike traditional security tools built for penetration testers, WebShield is designed for **developers and site owners** who want to understand and improve their site's security posture quickly.

---

## ✨ Why WebShield?

| Feature | WebShield | Other Tools |
|---|---|---|
| Security Score (0–100) | ✅ | ❌ |
| Letter Grade (A+ to F) | ✅ | ❌ |
| Code-level fix examples | ✅ | ❌ |
| JWT token analysis | ✅ | ❌ |
| Supply chain CVE check | ✅ | ❌ |
| GraphQL security testing | ✅ | Partial |
| Beautiful terminal output | ✅ | ❌ |
| Shareable HTML report | ✅ | Partial |
| Single `pip install` | ✅ | ❌ |
| CI/CD integration | ✅ | Partial |

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

# From source
git clone https://github.com/AKIB473/webshield.git
cd webshield
pip install -e .
```

**Requirements:** Python 3.9+ · No external tools needed · Single pip install

---

## 🔍 Usage

### Basic Scan
```bash
webshield scan https://example.com
```

### Full Scan with Reports
```bash
webshield scan https://example.com \
  --output report.html \
  --json results.json
```

### Scan Specific Modules
```bash
webshield scan https://example.com --modules ssl_tls,headers,cors,csp
```

### CI/CD Integration (Exit 1 on High+ findings)
```bash
webshield scan https://example.com --ci --fail-on high
echo $?  # 0 = pass, 1 = fail
```

### List All Available Modules
```bash
webshield list-modules
```

---

## 🧩 Modules

| Module | What It Checks |
|---|---|
| `ssl_tls` | Certificate validity/expiry, TLS version, cipher strength, self-signed |
| `headers` | All 8 security headers + dangerous info-leaking headers |
| `cookies` | Secure, HttpOnly, SameSite flags, weak session IDs |
| `info_leak` | .env, .git, backup files, SQL dumps, config files exposed |
| `sensitive_paths` | Admin panels, phpMyAdmin, Spring Actuator, debug interfaces |
| `cors` | Wildcard origins, reflected origins with credentials, null origin |
| `csp` | Full CSP directive analysis, unsafe-inline, unsafe-eval, wildcards |
| `dns_email` | SPF, DMARC, CAA records — email spoofing protection |
| `waf_detect` | Detects 15+ WAF vendors (Cloudflare, AWS, Akamai, ModSecurity...) |
| `tech_fingerprint` | Framework/CMS/server detection + CVE version matching |
| `open_redirect` | 22 common redirect parameters tested for open redirects |
| `http_methods` | Dangerous methods: PUT, DELETE, TRACE, CONNECT |
| `jwt` | alg:none, weak secrets, missing expiry, sensitive payload data |
| `subdomain_takeover` | CNAME → unclaimed GitHub Pages, Heroku, S3, Netlify, Azure... |
| `graphql` | Introspection, batch queries, depth DoS, GET-based CSRF |
| `request_smuggling` | CL.TE and TE.CL timing-based detection |
| `supply_chain` | package.json / requirements.txt scanned for CVE-affected deps |

---

## 📊 Example Output

```
🛡️ WebShield scanning https://example.com

╭─ Scan Summary ────────────────────────────────────────────────────╮
│  Target:  https://example.com                                     │
│  Score:   62/100  ████████████████░░░░░░░░░░░░░░░░░░░░░░░░       │
│  Grade:   C+                                                      │
│  Time:    8.3s  |  Modules: 17  |  Findings: 14                  │
╰───────────────────────────────────────────────────────────────────╯

🔴 CRITICAL (1)
  ■ Exposed .env File
    The .env file is publicly accessible. This typically contains
    database passwords, API keys, and secret keys.
    Evidence: HTTP 200 at https://example.com/.env — 412 bytes
    Fix: location ~ /\.env { deny all; return 404; }

🟠 HIGH (3)
  ■ Missing Security Header: Strict-Transport-Security
  ...
```

---

## 🔗 CI/CD Integration

### GitHub Actions
```yaml
name: Security Audit

on: [push, pull_request]

jobs:
  webshield:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run WebShield
        run: |
          pip install webshield
          webshield scan ${{ vars.SITE_URL }} \
            --ci --fail-on high \
            --json results.json \
            --output report.html

      - name: Upload Report
        if: always()
        uses: actions/upload-artifact@v4
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

result = run_scan("https://example.com")

print(f"Score: {result.score}/100 — Grade: {result.grade}")
print(f"Findings: {len(result.findings)}")

for f in result.findings:
    print(f"[{f.severity.value}] {f.title}")

# Save HTML report
save_html(result, "report.html")

# Export JSON
import json
with open("results.json", "w") as fp:
    json.dump(result.to_dict(), fp, indent=2)
```

---

## 🛠️ Ethical Use

WebShield is designed for **owners and authorized security testers** of websites.

- ✅ Scan your own sites
- ✅ Scan sites you have written permission to test
- ❌ Do not scan sites without permission
- ❌ Do not use findings to attack others

---

## 📄 License

MIT — see [LICENSE](LICENSE)

---

## 👤 Author

**AKIBUZZAMAN AKIB**
- GitHub: [@AKIB473](https://github.com/AKIB473)

---

## 🌟 Star History

If WebShield helped you, please give it a ⭐ — it helps others find it!

[![Star History Chart](https://api.star-history.com/svg?repos=AKIB473/webshield&type=Date)](https://star-history.com/#AKIB473/webshield)
