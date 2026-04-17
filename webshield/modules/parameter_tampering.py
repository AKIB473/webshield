"""Parameter Tampering Module (v1.8.0) — ZAP rule 40008"""
from __future__ import annotations
import re
from typing import List
from urllib.parse import urlparse, parse_qs, urlencode
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

PRICE_PARAMS  = re.compile(r"price|amount|cost|total|qty|quantity|fee|charge|discount", re.I)
ROLE_PARAMS   = re.compile(r"role|admin|isadmin|is_admin|privilege|group|permission|access", re.I)
HIDDEN_PATTERN= re.compile(r'<input[^>]+type=["\']?hidden["\']?[^>]*name=["\']?([^"\'>\s]+)["\']?[^>]*value=["\']?([^"\'>\s]*)["\']?', re.I)


def _try_price_tamper(client, url, fname, fval):
    try:
        r = client.post(
            url,
            content=f"{fname}=0&{fname}=-1&{fname}=0.01".encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if r.status_code == 200 and "error" not in r.text.lower():
            return Finding(
                title=f"Parameter Tampering — Price/Amount Field: {fname}",
                severity=Severity.HIGH,
                description=(
                    f"Hidden field '{fname}'='{fval}' was tampered to 0 and server accepted it. "
                    "This may allow purchasing items for free or at negative prices."
                ),
                evidence=f"Field: {fname}={fval} → tampered to 0, server HTTP 200",
                remediation="Never trust client-side price values. Recalculate from DB.",
                code_fix=(
                    "# ❌ Vulnerable:\nprice = request.form['price']\n\n"
                    "# ✅ Safe:\nproduct = Product.objects.get(id=request.form['product_id'])\n"
                    "price = product.price  # always from DB"
                ),
                reference="https://owasp.org/www-project-web-security-testing-guide/",
                module="parameter_tampering",
                cvss=8.1,
            )
    except Exception:
        pass
    return None


def _try_role_escalation(client, url, fname):
    for escalation in ["admin", "1", "true", "superuser", "administrator"]:
        try:
            r = client.post(
                url,
                content=f"{fname}={escalation}".encode(),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            if r.status_code == 200 and re.search(r"admin|dashboard|welcome", r.text, re.I):
                return Finding(
                    title=f"Parameter Tampering — Privilege Escalation via: {fname}={escalation}",
                    severity=Severity.CRITICAL,
                    description=(
                        f"Setting hidden field '{fname}' to '{escalation}' returned admin content. "
                        "Mass assignment or client-side role trust detected."
                    ),
                    evidence=f"Field: {fname}={escalation} → admin content in response",
                    remediation="Never accept role/privilege fields from client.",
                    code_fix=(
                        "# Use server-side session permissions only:\n"
                        "if not request.user.is_staff:\n    return HttpResponseForbidden()"
                    ),
                    reference="https://owasp.org/www-project-web-security-testing-guide/",
                    module="parameter_tampering",
                    cvss=9.1,
                )
        except Exception:
            continue
    return None


def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    params = parse_qs(parsed.query, keep_blank_values=True)

    with get_client(timeout=min(timeout, 8.0)) as client:
        # 1. Check hidden form fields
        try:
            resp = client.get(url)
            for (fname, fval) in HIDDEN_PATTERN.findall(resp.text)[:5]:
                if PRICE_PARAMS.search(fname):
                    f = _try_price_tamper(client, url, fname, fval)
                    if f:
                        findings.append(f)
                if ROLE_PARAMS.search(fname):
                    f = _try_role_escalation(client, url, fname)
                    if f:
                        findings.append(f)
        except Exception:
            pass

        # 2. URL param tampering
        for pname, pvals in list(params.items())[:3]:
            orig = pvals[0] if pvals else "1"
            if PRICE_PARAMS.search(pname):
                for tamper in ["0", "-1", "0.001", "99999"]:
                    try:
                        new_params = {k: v for k, v in params.items()}
                        new_params[pname] = [tamper]
                        r = client.get(f"{base_url}{parsed.path}?{urlencode(new_params, doseq=True)}")
                        if r.status_code == 200 and tamper in r.text:
                            findings.append(Finding(
                                title=f"Parameter Tampering — URL Price Param: {pname}={tamper}",
                                severity=Severity.HIGH,
                                description=f"URL param '{pname}' tampered to '{tamper}', reflected without validation.",
                                evidence=f"Original: {pname}={orig} → Tampered: {pname}={tamper}, HTTP 200",
                                remediation="Validate and enforce amount/price server-side.",
                                code_fix="price = max(0.01, float(request.args.get('price', 0)))\n# Better: derive from product DB",
                                reference="https://owasp.org/www-project-web-security-testing-guide/",
                                module="parameter_tampering",
                                cvss=7.5,
                            ))
                            break
                    except Exception:
                        continue

    return findings
