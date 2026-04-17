"""Dangerous JavaScript Functions & Reverse Tabnabbing Module (v1.8.0) — ZAP rules 10108/10110"""
from __future__ import annotations
import re
from typing import List
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

DANGEROUS_FUNCS = [
    (re.compile(r'\beval\s*\(', re.I),                          "eval()",              "Arbitrary code execution if input reaches eval()",         Severity.MEDIUM, 6.1),
    (re.compile(r'document\.write\s*\(', re.I),                 "document.write()",    "DOM XSS risk; often used for script injection",            Severity.MEDIUM, 5.3),
    (re.compile(r'innerHTML\s*=', re.I),                        "innerHTML assignment","Direct DOM XSS if user data flows here",                   Severity.MEDIUM, 6.1),
    (re.compile(r'outerHTML\s*=', re.I),                        "outerHTML assignment","DOM XSS via outerHTML replacement",                        Severity.MEDIUM, 5.3),
    (re.compile(r'window\.location\s*=\s*[^;]+\bparam|hash|search', re.I), "window.location from URL", "Open redirect or XSS if URL params flow to location", Severity.MEDIUM, 6.1),
    (re.compile(r'setTimeout\s*\(\s*["\']', re.I),              "setTimeout(string)",  "Code injection via string argument to setTimeout",        Severity.MEDIUM, 5.3),
    (re.compile(r'setInterval\s*\(\s*["\']', re.I),             "setInterval(string)", "Code injection via string argument to setInterval",       Severity.MEDIUM, 5.3),
    (re.compile(r'new\s+Function\s*\(', re.I),                  "new Function()",      "Similar to eval — arbitrary code execution risk",         Severity.MEDIUM, 6.1),
    (re.compile(r'\.html\s*\(.*?(location|param|query)', re.I), "jQuery .html() with URL data","DOM XSS via jQuery html() with URL parameters",  Severity.HIGH,   7.5),
    (re.compile(r'postMessage\s*\((?!.*targetOrigin)', re.I),   "postMessage no targetOrigin","Missing targetOrigin allows message to any origin", Severity.MEDIUM, 5.3),
]

TABNABBING_PATTERN = re.compile(
    r'<a\b[^>]+target\s*=\s*["\']_blank["\'][^>]*>',
    re.I
)
NOOPENER_PATTERN = re.compile(r'rel\s*=\s*["\'][^"\']*noopener', re.I)
NOREFERRER_PATTERN = re.compile(r'rel\s*=\s*["\'][^"\']*noreferrer', re.I)

def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    with get_client(timeout=min(timeout, 8.0)) as client:
        try:
            resp = client.get(url)
            if resp.status_code != 200:
                return findings
            body = resp.text[:100000]

            # Check dangerous JS functions
            func_hits = []
            for (pattern, func_name, risk, severity, cvss) in DANGEROUS_FUNCS:
                m = pattern.search(body)
                if m:
                    ctx = body[max(0, m.start()-30):m.end()+60].strip()
                    func_hits.append((func_name, risk, ctx))

            if len(func_hits) >= 2:
                findings.append(Finding(
                    title=f"Dangerous JavaScript Functions Detected ({len(func_hits)} found)",
                    severity=Severity.MEDIUM,
                    description=(
                        f"The following potentially dangerous JavaScript functions were found:\n"
                        + "\n".join(f"• {n}: {r}" for n,r,_ in func_hits[:5])
                    ),
                    evidence="\n".join(f"{n}: ...{ctx}..." for n,_,ctx in func_hits[:3]),
                    remediation=(
                        "Audit all uses of eval(), innerHTML, document.write(), and setTimeout(string). "
                        "Ensure no user-controlled data flows into these sinks."
                    ),
                    code_fix=(
                        "// ❌ eval with user input:\neval(userInput)\n\n"
                        "// ✅ Use JSON.parse for data, never eval:\nconst data = JSON.parse(userInput);\n\n"
                        "// ❌ innerHTML with user data:\nel.innerHTML = userContent;\n\n"
                        "// ✅ Use textContent:\nel.textContent = userContent;"
                    ),
                    reference="https://owasp.org/www-community/attacks/DOM_Based_XSS",
                    module="dangerous_js",
                    cvss=6.1,
                ))

            # Check reverse tabnabbing
            blank_links = TABNABBING_PATTERN.findall(body)
            vulnerable_links = [
                tag for tag in blank_links
                if not NOOPENER_PATTERN.search(tag) and not NOREFERRER_PATTERN.search(tag)
            ]
            if len(vulnerable_links) >= 2:
                findings.append(Finding(
                    title=f"Reverse Tabnabbing — {len(vulnerable_links)} Links Without rel='noopener'",
                    severity=Severity.MEDIUM,
                    description=(
                        f"{len(vulnerable_links)} links use target='_blank' without rel='noopener noreferrer'. "
                        "The opened page gets a reference to the opener via window.opener, "
                        "allowing it to redirect the original tab to a phishing page."
                    ),
                    evidence=f"Example: {vulnerable_links[0][:120]}",
                    remediation="Add rel='noopener noreferrer' to all target='_blank' links.",
                    code_fix=(
                        "<!-- ❌ Vulnerable: -->\n<a href='https://external.com' target='_blank'>Link</a>\n\n"
                        "<!-- ✅ Safe: -->\n<a href='https://external.com' target='_blank' rel='noopener noreferrer'>Link</a>"
                    ),
                    reference="https://owasp.org/www-community/attacks/Reverse_Tabnabbing",
                    module="dangerous_js",
                    cvss=4.3,
                ))
        except Exception:
            pass
    return findings
