"""
Prototype Pollution Detection Module
Tests query params and JSON bodies for JS prototype pollution.
Learned from: wshawk (proto_polluter.py — unique, best implementation)
"""

from __future__ import annotations
import json
from typing import List
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

# Prototype pollution payloads via query string
QUERY_PAYLOADS = [
    ("__proto__[webshield]", "pptest"),
    ("constructor[prototype][webshield]", "pptest"),
    ("__proto__.webshield", "pptest"),
]

# JSON body payloads
JSON_PAYLOADS = [
    {"__proto__": {"webshield": "pptest"}},
    {"constructor": {"prototype": {"webshield": "pptest"}}},
    {"__proto__": {"isAdmin": True}},
]

# Indicators that pollution succeeded
PP_INDICATORS = [
    "pptest",
    '"webshield"',
    '"isAdmin":true',
    '"isAdmin": true',
    "prototype",
]


def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    parsed = urlparse(url)
    base = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
    existing = parse_qs(parsed.query, keep_blank_values=True)

    with get_client(timeout=timeout) as client:
        # 1. Query string prototype pollution
        for (key, val) in QUERY_PAYLOADS:
            new_params = dict(existing)
            new_params[key] = [val]
            test_url = base + "?" + urlencode(
                {k: v[0] if isinstance(v, list) else v for k, v in new_params.items()}
            )
            try:
                resp = client.get(test_url)
                body = resp.text
                if any(ind in body for ind in PP_INDICATORS):
                    findings.append(Finding(
                        title="Prototype Pollution via Query String",
                        severity=Severity.HIGH,
                        description=(
                            "The application reflects prototype pollution payloads from "
                            "query parameters. Attackers can pollute JavaScript Object "
                            "prototypes to bypass security checks, escalate privileges "
                            "(isAdmin: true), or cause denial of service."
                        ),
                        evidence=(
                            f"Payload: {key}={val}\n"
                            f"Indicator found in response body."
                        ),
                        remediation=(
                            "Sanitize query parameters before using them as object keys. "
                            "Freeze the Object prototype: Object.freeze(Object.prototype). "
                            "Use Map instead of plain objects for user-controlled keys."
                        ),
                        code_fix=(
                            "// Freeze prototype to prevent pollution:\n"
                            "Object.freeze(Object.prototype);\n\n"
                            "// Validate keys before assignment:\n"
                            "const BANNED = ['__proto__', 'constructor', 'prototype'];\n"
                            "function safe_assign(obj, key, val) {\n"
                            "    if (BANNED.includes(key)) return;\n"
                            "    obj[key] = val;\n"
                            "}\n\n"
                            "// Use Object.create(null) for dictionaries:\n"
                            "const safe = Object.create(null);"
                        ),
                        reference="https://portswigger.net/web-security/prototype-pollution",
                        cvss=7.3,
                    ))
                    return findings
            except Exception:
                continue

        # 2. JSON body prototype pollution
        for payload in JSON_PAYLOADS[:2]:
            try:
                resp = client.post(
                    url,
                    content=json.dumps(payload),
                    headers={"Content-Type": "application/json"},
                )
                body = resp.text
                if any(ind in body for ind in PP_INDICATORS):
                    findings.append(Finding(
                        title="Prototype Pollution via JSON Body",
                        severity=Severity.HIGH,
                        description=(
                            "The application reflects prototype pollution payloads from "
                            "JSON request bodies. This can allow privilege escalation or "
                            "application logic bypass."
                        ),
                        evidence=(
                            f"Payload: {json.dumps(payload)}\n"
                            f"Indicator found in response."
                        ),
                        remediation=(
                            "Validate JSON keys against a whitelist. Reject requests "
                            "containing '__proto__', 'constructor', or 'prototype' as keys."
                        ),
                        code_fix=(
                            "# Python — sanitize JSON keys:\n"
                            "BANNED = {'__proto__', 'constructor', 'prototype'}\n"
                            "def sanitize(obj):\n"
                            "    if isinstance(obj, dict):\n"
                            "        return {k: sanitize(v) for k, v in obj.items()\n"
                            "                if k not in BANNED}\n"
                            "    return obj"
                        ),
                        reference="https://portswigger.net/web-security/prototype-pollution",
                        cvss=7.3,
                    ))
                    return findings
            except Exception:
                continue

    return findings
