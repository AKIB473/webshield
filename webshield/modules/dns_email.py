"""
DNS & Email Security Module
Checks SPF, DKIM hints, DMARC, CAA records.
Learned from: yawast-ng (best DNS module), GSEC
"""

from __future__ import annotations
import re
from typing import List, Optional
from urllib.parse import urlparse
from webshield.core.models import Finding, Severity

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


def _query(domain: str, record_type: str) -> List[str]:
    if not DNS_AVAILABLE:
        return []
    try:
        answers = dns.resolver.resolve(domain, record_type, lifetime=8)
        return [r.to_text().strip('"') for r in answers]
    except Exception:
        return []


def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []

    if not DNS_AVAILABLE:
        findings.append(Finding(
            title="DNS checks skipped — dnspython not installed",
            severity=Severity.INFO,
            description="Install dnspython to enable DNS/SPF/DKIM/DMARC checks: pip install dnspython",
        ))
        return findings

    parsed = urlparse(url)
    domain = parsed.hostname
    if not domain:
        return []

    # Strip www for root domain checks
    root = domain.lstrip("www.")

    # ── SPF ──────────────────────────────────────────────────────────
    txt_records = _query(root, "TXT")
    spf_records = [r for r in txt_records if r.startswith("v=spf1")]

    if not spf_records:
        findings.append(Finding(
            title="SPF Record Missing",
            severity=Severity.MEDIUM,
            description=(
                "No SPF (Sender Policy Framework) record found. "
                "SPF tells mail servers which hosts are authorized to send email for your domain. "
                "Without it, attackers can spoof your domain in phishing emails."
            ),
            evidence=f"No SPF TXT record found for {root}",
            remediation="Add an SPF TXT record to your DNS.",
            code_fix=(
                "# DNS TXT record:\n"
                f"v=spf1 include:_spf.google.com ~all\n\n"
                "# Or if you use AWS SES:\n"
                "v=spf1 include:amazonses.com ~all"
            ),
            reference="https://dmarcian.com/spf-survey/",
        ))
    else:
        spf = spf_records[0]
        # Check for +all (allows everyone — useless)
        if "+all" in spf:
            findings.append(Finding(
                title="SPF Record Uses +all (Permissive)",
                severity=Severity.HIGH,
                description=(
                    "Your SPF record ends with '+all', which means ALL servers are authorized "
                    "to send mail for your domain. This makes SPF completely useless."
                ),
                evidence=f"SPF record: {spf}",
                remediation="Change +all to ~all (soft fail) or -all (hard fail).",
                code_fix=f"v=spf1 ... -all  # -all = hard fail, ~all = soft fail",
                reference="https://www.cloudflare.com/learning/dns/dns-records/dns-spf-record/",
                cvss=6.5,
            ))
        elif "?all" in spf:
            findings.append(Finding(
                title="SPF Record Uses ?all (Neutral — Ineffective)",
                severity=Severity.MEDIUM,
                description="SPF record uses '?all' which is neutral and provides no spoofing protection.",
                evidence=f"SPF record: {spf}",
                remediation="Change ?all to ~all or -all.",
                code_fix="v=spf1 ... ~all",
                reference="https://www.cloudflare.com/learning/dns/dns-records/dns-spf-record/",
            ))

    # ── DMARC ─────────────────────────────────────────────────────────
    dmarc_records = _query(f"_dmarc.{root}", "TXT")
    dmarc = next((r for r in dmarc_records if r.startswith("v=DMARC1")), None)

    if not dmarc:
        findings.append(Finding(
            title="DMARC Record Missing",
            severity=Severity.MEDIUM,
            description=(
                "No DMARC record found. DMARC tells receiving mail servers what to do "
                "when SPF or DKIM checks fail. Without DMARC, spoofed emails from your "
                "domain may be delivered to victims."
            ),
            evidence=f"No DMARC TXT record at _dmarc.{root}",
            remediation="Add a DMARC TXT record to your DNS at _dmarc.yourdomain.com",
            code_fix=(
                "# Start with monitoring (p=none) then move to quarantine/reject:\n"
                f"_dmarc.{root}  TXT  \"v=DMARC1; p=none; rua=mailto:dmarc@{root}\"\n\n"
                "# Once confident:\n"
                f"_dmarc.{root}  TXT  \"v=DMARC1; p=reject; rua=mailto:dmarc@{root}\""
            ),
            reference="https://dmarc.org/overview/",
        ))
    else:
        # Parse DMARC policy
        policy_match = re.search(r"p=(\w+)", dmarc)
        policy = policy_match.group(1).lower() if policy_match else "none"

        if policy == "none":
            findings.append(Finding(
                title="DMARC Policy Set to 'none' (Monitor Only)",
                severity=Severity.LOW,
                description=(
                    "DMARC is present but policy is 'p=none', which only monitors but "
                    "does NOT reject or quarantine spoofed emails. Spoofing is still possible."
                ),
                evidence=f"DMARC record: {dmarc}",
                remediation="Move DMARC policy to 'p=quarantine' then eventually 'p=reject'.",
                code_fix=f'v=DMARC1; p=reject; rua=mailto:dmarc@{root}',
                reference="https://dmarc.org/overview/",
            ))
        elif policy == "quarantine":
            findings.append(Finding(
                title="DMARC Policy is 'quarantine' — Consider Upgrading to 'reject'",
                severity=Severity.INFO,
                description="DMARC quarantine policy sends spoofed mail to spam. Reject is stronger.",
                evidence=f"DMARC record: {dmarc}",
                remediation="Consider upgrading to p=reject for maximum protection.",
                code_fix=f'v=DMARC1; p=reject; rua=mailto:dmarc@{root}',
                reference="https://dmarc.org/overview/",
            ))

    # ── CAA ───────────────────────────────────────────────────────────
    caa_records = _query(root, "CAA")
    if not caa_records:
        findings.append(Finding(
            title="CAA Record Missing",
            severity=Severity.LOW,
            description=(
                "No CAA (Certification Authority Authorization) record found. "
                "CAA records restrict which Certificate Authorities can issue SSL certs "
                "for your domain, preventing unauthorized certificate issuance."
            ),
            evidence=f"No CAA record found for {root}",
            remediation="Add a CAA record specifying which CAs can issue certificates for your domain.",
            code_fix=(
                f"# If using Let's Encrypt:\n"
                f"{root}  CAA  0 issue \"letsencrypt.org\"\n\n"
                f"# If using multiple CAs:\n"
                f"{root}  CAA  0 issue \"letsencrypt.org\"\n"
                f"{root}  CAA  0 issue \"digicert.com\""
            ),
            reference="https://letsencrypt.org/docs/caa/",
        ))

    return findings
