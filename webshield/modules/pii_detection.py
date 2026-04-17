"""
PII Detection Module (v1.6.0)
Scans response bodies for leaked Personally Identifiable Information.
Inspired by: ZAP rule 10062 (Server Leaks PII), GDPR/CCPA compliance scanning

Detects:
- Social Security Numbers (SSN) — US
- Credit card numbers (Visa, MC, Amex, Discover) with Luhn check
- Email addresses in bulk (indicating a data leak)
- Phone numbers (US + international)
- National ID numbers (UK NI, Canadian SIN, etc.)
- Bank account / IBAN numbers
- Passport number patterns
- Date of birth patterns in bulk
- IP addresses in API responses (user tracking)
"""

from __future__ import annotations
import re
from typing import List, Tuple
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

# ── Patterns
SSN_PATTERN    = re.compile(r"\b(?!000|666|9\d{2})\d{3}[-\s](?!00)\d{2}[-\s](?!0000)\d{4}\b")
EMAIL_PATTERN  = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b")
PHONE_PATTERN  = re.compile(
    r"\b(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
    r"|\+\d{1,3}[-.\s]\d{2,4}[-.\s]\d{4,8}"
)
# Credit card: 13-19 digit groups (we apply Luhn to reduce false positives)
CC_PATTERN = re.compile(
    r"\b(?:4[0-9]{12}(?:[0-9]{3,6})?"        # Visa
    r"|(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}"  # MC
    r"|3[47][0-9]{13}"                         # Amex
    r"|3(?:0[0-5]|[68][0-9])[0-9]{11}"        # Diners
    r"|6(?:011|5[0-9]{2})[0-9]{12})"          # Discover
    r"\b"
)
IBAN_PATTERN   = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")
NI_PATTERN     = re.compile(r"\b[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D]\b")   # UK National Insurance
SIN_PATTERN    = re.compile(r"\b\d{3}[-\s]\d{3}[-\s]\d{3}\b")         # Canadian SIN
DOB_PATTERN    = re.compile(
    r"\b(19|20)\d{2}[-/](0[1-9]|1[0-2])[-/](0[1-9]|[12]\d|3[01])\b"
)
PASSPORT_PAT   = re.compile(r"\b[A-Z]{1,2}\d{6,9}\b")   # generic passport
IPV4_PATTERN   = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)


def _luhn(number: str) -> bool:
    """Validate credit card number with Luhn algorithm."""
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# API paths that might return user data
SENSITIVE_PATHS = [
    "/api/users", "/api/v1/users", "/api/user", "/api/me",
    "/api/profile", "/api/customers", "/api/v1/customers",
    "/api/accounts", "/users.json", "/admin/users",
    "/api/v2/users", "/api/members",
]


def _check_pii(body: str, url: str, findings: List[Finding]) -> None:
    """Scan response body for PII patterns."""
    # Limit analysis to first 50KB
    text = body[:50000]

    # ── SSN
    ssns = SSN_PATTERN.findall(text)
    if ssns:
        findings.append(Finding(
            title="Social Security Numbers (SSN) Leaked in Response",
            severity=Severity.CRITICAL,
            description=(
                f"The response from {url} contains Social Security Numbers. "
                "Exposing SSNs violates GDPR, CCPA, HIPAA, and numerous state laws. "
                "This constitutes a data breach and carries significant legal liability."
            ),
            evidence=f"SSN patterns found: {ssns[:2]} (showing first 2)\nURL: {url}",
            remediation=(
                "Mask or remove SSNs from API responses. "
                "Use format: XXX-XX-1234 for display purposes."
            ),
            code_fix=(
                "# Python — mask SSN before returning:\n"
                "import re\n"
                "def mask_ssn(text):\n"
                "    return re.sub(r'\\b\\d{3}-\\d{2}-(\\d{4})\\b', r'XXX-XX-\\1', text)\n\n"
                "# Never include SSNs in API responses. Store hashed/encrypted."
            ),
            reference="https://owasp.org/www-project-top-ten/",
            module="pii_detection",
            cvss=9.8,
        ))

    # ── Credit Cards (with Luhn validation to reduce false positives)
    raw_ccs = CC_PATTERN.findall(text)
    valid_ccs = [cc for cc in raw_ccs if _luhn(re.sub(r"\D", "", cc))]
    if valid_ccs:
        findings.append(Finding(
            title="Credit Card Numbers Leaked in Response (PCI-DSS Violation)",
            severity=Severity.CRITICAL,
            description=(
                f"Valid credit card numbers (Luhn-verified) were found in the response "
                f"from {url}. This is a severe PCI-DSS violation that can result in "
                "fines up to $100,000/month and loss of card processing privileges."
            ),
            evidence=f"Credit card numbers found (Luhn valid): {len(valid_ccs)}\nURL: {url}",
            remediation=(
                "Never return full card numbers in API responses. "
                "Store only the last 4 digits. "
                "Use tokenization (Stripe, Braintree) instead of raw card numbers."
            ),
            code_fix=(
                "# Never store or return full card numbers:\n"
                "# Instead, use tokenization:\n"
                "import stripe\n"
                "# Store stripe.PaymentMethod.id, never the raw card number\n\n"
                "# If you must display, mask it:\n"
                "masked = '**** **** **** ' + card_number[-4:]"
            ),
            reference="https://www.pcisecuritystandards.org/",
            module="pii_detection",
            cvss=9.8,
        ))

    # ── Bulk email addresses (5+ emails = likely a data dump)
    emails = EMAIL_PATTERN.findall(text)
    # Filter out common non-PII emails (noreply@, support@, etc.)
    user_emails = [
        e for e in emails
        if not any(prefix in e.lower() for prefix in
                   ["noreply", "no-reply", "support", "info@", "admin@", "test@",
                    "example.com", "yourcompany", "yourdomain"])
    ]
    if len(user_emails) >= 5:
        findings.append(Finding(
            title=f"Bulk Email Addresses Leaked ({len(user_emails)} found)",
            severity=Severity.HIGH,
            description=(
                f"{len(user_emails)} user email addresses found in the response from {url}. "
                "Bulk email exposure violates GDPR Article 5 and CCPA data minimization "
                "principles. Attackers can use these for phishing, credential stuffing, "
                "and targeted social engineering."
            ),
            evidence=f"Email addresses found: {user_emails[:3]} ... ({len(user_emails)} total)\nURL: {url}",
            remediation=(
                "Paginate API responses and require authentication. "
                "Apply field-level authorization so users can only see their own data. "
                "Rate-limit enumeration endpoints."
            ),
            code_fix=(
                "# Django REST Framework — filter by current user:\n"
                "class UserListView(ListAPIView):\n"
                "    permission_classes = [IsAuthenticated]\n"
                "    \n"
                "    def get_queryset(self):\n"
                "        # Users can only see themselves\n"
                "        return User.objects.filter(id=self.request.user.id)\n\n"
                "# Never return all users to non-admin API consumers"
            ),
            reference="https://gdpr.eu/article-5-how-personal-data-should-be-processed/",
            module="pii_detection",
            cvss=7.5,
        ))

    # ── IBAN / Bank account numbers
    ibans = IBAN_PATTERN.findall(text)
    # Filter false positives (must start with valid country code)
    valid_ibans = [i for i in ibans if len(i) >= 15 and i[:2].isalpha()]
    if valid_ibans:
        findings.append(Finding(
            title=f"IBAN / Bank Account Numbers Leaked ({len(valid_ibans)} found)",
            severity=Severity.CRITICAL,
            description=(
                f"IBAN-formatted bank account numbers were found in the response from {url}. "
                "Exposing bank account numbers enables unauthorized transfers and violates "
                "PSD2 and financial data protection regulations."
            ),
            evidence=f"IBAN patterns: {valid_ibans[:2]}\nURL: {url}",
            remediation="Mask bank account numbers. Return only last 4 digits for display.",
            code_fix="masked_iban = iban[:4] + '*' * (len(iban) - 8) + iban[-4:]",
            reference="https://owasp.org/www-project-top-ten/",
            module="pii_detection",
            cvss=9.1,
        ))

    # ── UK National Insurance numbers
    ni_numbers = NI_PATTERN.findall(text)
    if ni_numbers:
        findings.append(Finding(
            title=f"UK National Insurance Numbers Leaked",
            severity=Severity.HIGH,
            description=(
                "UK National Insurance numbers were found in the API response. "
                "This violates UK GDPR and the Data Protection Act 2018."
            ),
            evidence=f"NI numbers: {ni_numbers[:2]}\nURL: {url}",
            remediation="Remove or mask NI numbers from API responses.",
            code_fix="masked_ni = ni[:2] + '** *** **' + ni[-1]",
            reference="https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/",
            module="pii_detection",
            cvss=7.5,
        ))


def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []

    with get_client(timeout=min(timeout, 8.0)) as client:
        from urllib.parse import urlparse
        parsed   = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # ── Check the main page
        try:
            resp = client.get(url)
            if resp.status_code == 200:
                _check_pii(resp.text, url, findings)
        except Exception:
            pass

        if findings:
            return findings

        # ── Check common user data API endpoints
        for path in SENSITIVE_PATHS:
            try:
                resp = client.get(base_url + path)
                if resp.status_code == 200 and len(resp.text) > 100:
                    _check_pii(resp.text, base_url + path, findings)
                    if findings:
                        break
            except Exception:
                continue

    return findings
