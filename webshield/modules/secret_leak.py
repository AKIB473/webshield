"""
Secret / Sensitive Data Leak Detection Module
Scans page source, JS files, and API responses for leaked credentials.
Learned from: wshawk (sensitive_finder.py — best pattern set found anywhere)
NEW in v1.1.0 — unique, no other standalone scanner does this cleanly.
"""

from __future__ import annotations
import re
from typing import List, Tuple
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

# (label, pattern, severity, high_confidence)
SECRET_PATTERNS: List[Tuple[str, str, Severity, bool]] = [
    # Cloud providers
    ("AWS Access Key ID",          r"(?:AKIA|A3T[A-Z0-9])[A-Z0-9]{16}",                           Severity.CRITICAL, True),
    ("AWS Secret Access Key",      r"(?i)aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key[\s=:\"']+([A-Za-z0-9/+=]{40})", Severity.CRITICAL, True),
    ("Google API Key",             r"AIza[0-9A-Za-z\-_]{35}",                                     Severity.CRITICAL, True),
    ("Google OAuth Client",        r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",       Severity.HIGH, True),
    ("Firebase URL",               r"https://[a-z0-9\-]+\.firebaseio\.com",                        Severity.MEDIUM, True),
    # Version control & CI
    ("GitHub Personal Token",      r"ghp_[A-Za-z0-9_]{35,}",                                      Severity.CRITICAL, True),
    ("GitHub OAuth Token",         r"gho_[A-Za-z0-9_]{35,}",                                      Severity.CRITICAL, True),
    ("GitHub Actions Token",       r"ghs_[A-Za-z0-9_]{35,}",                                      Severity.CRITICAL, True),
    # Payment
    ("Stripe Secret Key",          r"sk_live_[0-9a-zA-Z]{24,99}",                                 Severity.CRITICAL, True),
    ("Stripe Publishable Key",     r"pk_live_[0-9a-zA-Z]{24,99}",                                 Severity.MEDIUM,   True),
    ("PayPal/Braintree Token",     r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",        Severity.CRITICAL, True),
    # Messaging & SaaS
    ("Slack Bot Token",            r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}",         Severity.CRITICAL, True),
    ("Slack App Token",            r"xapp-[0-9]-[A-Z0-9]{10}-[0-9]+-[a-f0-9]{64}",               Severity.CRITICAL, True),
    ("Twilio Account SID",         r"AC[a-zA-Z0-9]{32}",                                          Severity.HIGH,     True),
    ("Twilio Auth Token",          r"(?i)twilio[^\s]*[\s=:\"']+([0-9a-fA-F]{32})",                Severity.CRITICAL, True),
    ("SendGrid API Key",           r"SG\.[a-zA-Z0-9\-_]{22,}\.[a-zA-Z0-9\-_]{43,}",              Severity.CRITICAL, True),
    ("Mailgun API Key",            r"key-[0-9a-zA-Z]{32}",                                        Severity.HIGH,     True),
    # Crypto & Private Keys
    ("RSA/EC Private Key",         r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",     Severity.CRITICAL, True),
    ("PGP Private Key",            r"-----BEGIN PGP PRIVATE KEY BLOCK-----",                      Severity.CRITICAL, True),
    # Database
    ("Database Connection String", r"(?:mysql|postgres(?:ql)?|mongodb|redis|sqlite)://[^\s\"'<>]{8,}", Severity.CRITICAL, True),
    # Infrastructure
    ("S3 Bucket URL",              r"https?://[a-zA-Z0-9.\-]+\.s3[.\-]?(?:[a-z0-9\-]*)\.amazonaws\.com", Severity.MEDIUM, True),
    ("Heroku API Key",             r"(?i)heroku[^\s]*[\s=:\"']+([0-9a-fA-F\-]{36})",              Severity.CRITICAL, True),
    # Generic secrets (lower confidence)
    ("Password in URL",            r"(?i)[?&](?:pass(?:word)?|pwd|secret|key)=[^&\s\"']{6,}",    Severity.HIGH,     False),
    ("Internal IPv4 Address",      r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b", Severity.LOW, False),
    ("Generic API Key Pattern",    r"(?i)(?:api[_\-]?key|apikey|api[_\-]?secret|app[_\-]?secret|app[_\-]?key|access[_\-]?key)[\s=:\"']+([A-Za-z0-9_\-]{20,})", Severity.HIGH, False),
    ("Bearer Token in Source",     r'(?i)(?:bearer|authorization)["\s:=]+([A-Za-z0-9\-._~+/]{20,})', Severity.HIGH, False),
]

# JS files to also check
JS_EXTENSIONS = (".js", ".ts", ".jsx", ".tsx", ".mjs")


def _scan_content(content: str, source: str) -> List[Finding]:
    """Scan a string for secret patterns."""
    findings: List[Finding] = []
    seen_labels: set = set()

    for (label, pattern, severity, high_confidence) in SECRET_PATTERNS:
        if label in seen_labels:
            continue
        matches = re.findall(pattern, content)
        if not matches:
            continue

        # For low confidence, require multiple matches or strong context
        if not high_confidence and len(matches) < 2:
            continue

        # Redact the actual secret value
        sample = str(matches[0])
        if len(sample) > 12:
            redacted = sample[:6] + "..." + sample[-4:]
        else:
            redacted = "[REDACTED]"

        seen_labels.add(label)
        findings.append(Finding(
            title=f"Secret Leaked in Page Source: {label}",
            severity=severity,
            description=(
                f"A {label} was found in the page source at {source}. "
                "Exposing credentials in client-side code or public pages allows "
                "attackers to directly access your services, cloud accounts, or databases."
            ),
            evidence=(
                f"Source: {source}\n"
                f"Pattern matched: {label}\n"
                f"Sample (redacted): {redacted}"
            ),
            remediation=(
                f"Remove the {label} from client-side code immediately. "
                "Store secrets in environment variables, a secrets manager (AWS Secrets Manager, "
                "HashiCorp Vault), or CI/CD secrets. Rotate the credential immediately."
            ),
            code_fix=(
                "# Python — use environment variables:\n"
                "import os\n"
                f"secret = os.environ['{label.upper().replace(' ','_')}']\n\n"
                "# Never hardcode secrets in source code or commit them to git.\n"
                "# Add .env to .gitignore:\n"
                "echo '.env' >> .gitignore"
            ),
            reference="https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
            cvss=9.8 if severity == Severity.CRITICAL else 7.5,
        ))

    return findings


def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []

    with get_client(timeout=timeout) as client:
        # Scan main page
        try:
            resp = client.get(url)
            findings.extend(_scan_content(resp.text, url))
        except Exception:
            return []

        # Extract and scan linked JS files
        js_urls = []
        import re as _re
        for match in _re.finditer(
            r'(?:src|href)=["\']([^"\']+\.(?:js|mjs)(?:\?[^"\']*)?)["\']',
            resp.text, _re.IGNORECASE
        ):
            js_path = match.group(1)
            if js_path.startswith("http"):
                js_urls.append(js_path)
            elif js_path.startswith("/"):
                from urllib.parse import urlparse as _up
                p = _up(url)
                js_urls.append(f"{p.scheme}://{p.netloc}{js_path}")

        for js_url in js_urls[:5]:  # check first 5 JS files
            try:
                js_resp = client.get(js_url)
                js_findings = _scan_content(js_resp.text, js_url)
                findings.extend(js_findings)
            except Exception:
                continue

    # Deduplicate by title
    seen = set()
    unique = []
    for f in findings:
        if f.title not in seen:
            seen.add(f.title)
            unique.append(f)
    return unique
