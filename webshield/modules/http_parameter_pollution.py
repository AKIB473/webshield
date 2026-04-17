"""
HTTP Parameter Pollution (HPP) Module (v1.6.0)
Detects parameter pollution vulnerabilities that bypass WAF, validation, and business logic.
Inspired by: ZAP rule 20014 (HTTP Parameter Pollution), PortSwigger HPP research

Attack types:
1. Duplicate parameters (?id=1&id=2) — server may use first, last, or both
2. Array notation (?id[]=1&id[]=2) — PHP/Ruby array handling
3. HPP in POST body combined with GET params
4. Parameter override attacks (WAF bypass: ?action=delete&action=view)
5. Business logic abuse via duplicates (?price=100&price=0)
6. Query string injection — escaping via duplicate keys
"""

from __future__ import annotations
import re
from typing import List
from urllib.parse import urlparse, parse_qs, urlencode, urljoin
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

# We look for params in the crawled URL that we can duplicate
PROBE_PARAMS = ["id", "page", "sort", "order", "action", "type", "user", "q", "search"]


def _get_params_from_url(url: str) -> dict:
    parsed = urlparse(url)
    return parse_qs(parsed.query, keep_blank_values=True)


def _build_base_url(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"


def _test_hpp(client, url: str, param: str, val: str, findings: List[Finding]) -> bool:
    """
    Test HTTP Parameter Pollution for a specific param.
    Returns True if a vulnerability was found.
    """
    base = _build_base_url(url)

    try:
        # Get baseline for single param
        r_baseline = client.get(f"{base}?{param}={val}")
        baseline_status = r_baseline.status_code
        baseline_body   = r_baseline.text
    except Exception:
        return False

    # ── Test 1: Duplicate parameter (most servers pick first or last)
    try:
        r_dup = client.get(f"{base}?{param}={val}&{param}=INJECTED")
        dup_body   = r_dup.text
        dup_status = r_dup.status_code

        # Check for response difference that indicates server processes second value
        if (dup_status == baseline_status and
                "INJECTED" in dup_body and dup_body != baseline_body):
            findings.append(Finding(
                title=f"HTTP Parameter Pollution — Duplicate Param Reflected ({param})",
                severity=Severity.MEDIUM,
                description=(
                    f"The server reflects the SECOND occurrence of duplicate parameter '{param}'. "
                    "This allows attackers to bypass WAF rules (WAF may check first param, "
                    "server uses second) and potentially override intended parameter values. "
                    "Commonly abused for: WAF bypass, price manipulation, access control bypass."
                ),
                evidence=(
                    f"URL: {base}?{param}={val}&{param}=INJECTED\n"
                    f"HTTP {dup_status}\n"
                    f"'INJECTED' value reflected in response"
                ),
                remediation=(
                    "Process only the first occurrence of each parameter server-side. "
                    "Never process duplicate parameters unless intentional (arrays)."
                ),
                code_fix=(
                    "# Python/Flask — use request.args.get() not request.args.getlist():\n"
                    "# ❌ Vulnerable — uses last value:\n"
                    "val = request.args['param']  # dict returns last in some frameworks\n\n"
                    "# ✅ Safe — explicitly get first:\n"
                    "val = request.args.getlist('param')[0] if 'param' in request.args else None\n\n"
                    "# Express.js:\n"
                    "// ❌ req.query may return array if duplicated\n"
                    "const val = Array.isArray(req.query.param)\n"
                    "    ? req.query.param[0]  // use first\n"
                    "    : req.query.param;"
                ),
                reference="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution",
                module="http_parameter_pollution",
                cvss=5.3,
            ))
            return True
    except Exception:
        pass

    # ── Test 2: Array notation bypass
    try:
        r_arr = client.get(f"{base}?{param}[]={val}&{param}[]=INJECTED")
        if r_arr.status_code == 200 and "INJECTED" in r_arr.text:
            findings.append(Finding(
                title=f"HTTP Parameter Pollution — Array Notation Bypass ({param}[])",
                severity=Severity.MEDIUM,
                description=(
                    f"The server processes array notation ({param}[]) for parameter '{param}'. "
                    "This can bypass input validation and WAF rules that check for single values."
                ),
                evidence=f"URL: {base}?{param}[]={val}&{param}[]=INJECTED → HTTP {r_arr.status_code}",
                remediation=(
                    "Validate that parameters are single values, not arrays, unless explicitly required. "
                    "Cast to string/int before validation."
                ),
                code_fix=(
                    "# PHP — prevent array injection:\n"
                    "// ❌ Vulnerable:\n"
                    "$id = $_GET['id'];  // could be array\n\n"
                    "// ✅ Safe:\n"
                    "$id = is_array($_GET['id']) ? $_GET['id'][0] : $_GET['id'];\n"
                    "$id = intval($id);  // cast to int"
                ),
                reference="https://owasp.org/www-project-web-security-testing-guide/",
                module="http_parameter_pollution",
                cvss=5.3,
            ))
            return True
    except Exception:
        pass

    # ── Test 3: Business logic — price/quantity manipulation via duplicate
    if param in ("price", "amount", "qty", "quantity", "total"):
        try:
            r_zero = client.get(f"{base}?{param}={val}&{param}=0")
            # If status 200 and response doesn't show error, may have accepted price=0
            if r_zero.status_code == 200 and "error" not in r_zero.text.lower():
                findings.append(Finding(
                    title=f"Business Logic: Price/Amount HPP Bypass ({param})",
                    severity=Severity.HIGH,
                    description=(
                        f"Duplicate {param} parameter with value=0 was accepted without error. "
                        "This may allow price manipulation attacks where the second value "
                        "overrides the validated first value."
                    ),
                    evidence=f"URL: {base}?{param}={val}&{param}=0 → HTTP {r_zero.status_code}",
                    remediation="Reject requests with duplicate critical parameters.",
                    code_fix=(
                        "# Explicitly reject duplicate params for sensitive fields:\n"
                        "if isinstance(request.args.getlist('price'), list) and len(request.args.getlist('price')) > 1:\n"
                        "    abort(400, 'Duplicate parameter not allowed')"
                    ),
                    reference="https://owasp.org/www-project-web-security-testing-guide/",
                    module="http_parameter_pollution",
                    cvss=7.5,
                ))
                return True
        except Exception:
            pass

    return False


def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []

    with get_client(timeout=min(timeout, 8.0)) as client:
        from urllib.parse import urlparse as _up
        params = _get_params_from_url(url)

        if not params:
            # No params in URL — try common ones against base
            base = _build_base_url(url)
            for p in PROBE_PARAMS[:5]:
                if _test_hpp(client, f"{base}?{p}=1", p, "1", findings):
                    break
        else:
            # Test each existing param
            for param, values in params.items():
                val = values[0] if values else "1"
                if _test_hpp(client, url, param, val, findings):
                    break

    return findings
