"""
Supply Chain / Dependency CVE Module — UNIQUE, no other standalone scanner has this
Fetches package.json or requirements.txt from the site and checks for known vulnerable deps.
"""

from __future__ import annotations
import json
import re
from typing import List, Dict, Optional
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

# Known vulnerable packages: (pkg, max_safe_version, cve, severity, description, cvss)
VULNERABLE_PACKAGES: List[tuple] = [
    # Python
    ("django",         "4.2.0",  "CVE-2023-23969", Severity.HIGH,     "Django < 4.2 DoS via Accept-Language header parsing.", 7.5),
    ("flask",          "2.3.0",  "CVE-2023-25577", Severity.HIGH,     "Werkzeug (Flask dep) < 2.3 path traversal.", 7.5),
    ("pillow",         "9.3.0",  "CVE-2022-45199", Severity.HIGH,     "Pillow < 9.3 heap buffer overflow.", 7.5),
    ("cryptography",   "41.0.0", "CVE-2023-49083", Severity.MEDIUM,   "cryptography < 41 NULL dereference.", 4.0),
    ("requests",       "2.28.0", "CVE-2023-32681", Severity.MEDIUM,   "Requests < 2.28 proxy header injection.", 6.1),
    ("paramiko",       "3.0.0",  "CVE-2023-48795", Severity.HIGH,     "Paramiko < 3.0 Terrapin SSH attack.", 5.9),
    ("pyyaml",         "6.0",    "CVE-2022-1471",  Severity.CRITICAL, "PyYAML < 6.0 arbitrary code execution via yaml.load.", 9.8),
    ("sqlalchemy",     "2.0.0",  "CVE-2023-48804", Severity.MEDIUM,   "SQLAlchemy < 2.0 SQL injection risk.", 6.5),
    ("jinja2",         "3.1.2",  "CVE-2024-22195", Severity.MEDIUM,   "Jinja2 < 3.1.2 XSS via xmlattr filter.", 5.4),
    # Node.js
    ("lodash",         "4.17.21","CVE-2021-23337", Severity.HIGH,     "lodash < 4.17.21 prototype pollution.", 7.2),
    ("axios",          "1.6.0",  "CVE-2023-45857", Severity.HIGH,     "axios < 1.6.0 CSRF token exposure.", 6.5),
    ("express",        "4.18.2", "CVE-2022-24999", Severity.HIGH,     "express < 4.18.2 qs prototype pollution.", 7.5),
    ("jsonwebtoken",   "9.0.0",  "CVE-2022-23529", Severity.CRITICAL, "jsonwebtoken < 9.0 secret injection via malformed header.", 9.8),
    ("minimist",       "1.2.6",  "CVE-2021-44906", Severity.CRITICAL, "minimist prototype pollution enables RCE.", 9.8),
    ("node-fetch",     "2.6.7",  "CVE-2022-0235",  Severity.HIGH,     "node-fetch < 2.6.7 SSRF via URL redirect.", 8.8),
    ("serialize-javascript","3.1.0","CVE-2020-7660",Severity.HIGH,    "serialize-javascript < 3.1.0 XSS.", 8.1),
    ("ansi-regex",     "6.0.1",  "CVE-2021-3807",  Severity.HIGH,     "ansi-regex < 6.0.1 ReDoS vulnerability.", 7.5),
    ("tar",            "6.1.9",  "CVE-2021-32803", Severity.HIGH,     "tar < 6.1.9 path traversal.", 8.1),
    ("semver",         "7.5.4",  "CVE-2022-25883", Severity.HIGH,     "semver < 7.5.4 ReDoS.", 7.5),
    ("postcss",        "8.4.31", "CVE-2023-44270", Severity.MEDIUM,   "postcss < 8.4.31 line return parsing issue.", 5.3),
    # 2024–2025 CVEs
    ("next",           "14.1.1", "CVE-2024-34351", Severity.HIGH,     "Next.js < 14.1.1 Server Actions SSRF.", 7.5),
    ("next",           "14.2.25","CVE-2025-29927", Severity.CRITICAL, "Next.js < 14.2.25 middleware auth bypass via x-middleware-subrequest.", 9.1),
    ("vite",           "5.4.15", "CVE-2025-30208", Severity.HIGH,     "Vite < 5.4.15 arbitrary file read via server.fs bypass.", 7.5),
    ("esbuild",        "0.25.0", "CVE-2025-25193", Severity.MEDIUM,   "esbuild < 0.25.0 dev server exposes files to network.", 5.3),
    ("path-to-regexp", "6.3.0",  "CVE-2024-45296", Severity.HIGH,     "path-to-regexp < 6.3.0 ReDoS vulnerability.", 7.5),
    ("dompurify",      "3.1.6", "CVE-2024-45801", Severity.HIGH,     "DOMPurify < 3.1.6 mXSS bypass.", 7.2),
    ("fastify",        "4.28.0", "CVE-2024-22207", Severity.HIGH,     "Fastify < 4.28.0 ReDoS in content-type.", 7.5),
    ("werkzeug",       "3.0.3",  "CVE-2024-34069", Severity.HIGH,     "Werkzeug < 3.0.3 debugger PIN bypass RCE.", 9.8),
    ("aiohttp",        "3.9.4",  "CVE-2024-23829", Severity.HIGH,     "aiohttp < 3.9.4 HTTP request smuggling.", 6.5),
    ("gradio",         "4.19.2", "CVE-2024-1727",  Severity.HIGH,     "Gradio < 4.19.2 arbitrary file read.", 7.5),
    ("langchain",      "0.2.0",  "CVE-2024-2965",  Severity.CRITICAL, "LangChain < 0.2.0 prompt injection / code execution.", 9.8),
]


def _version_less_than(v1: str, v2: str) -> bool:
    try:
        def norm(v: str) -> List[int]:
            # strip leading ^ ~ >= etc.
            v = re.sub(r"[^\d.]", "", v.split("-")[0])
            return [int(x) for x in v.split(".")[:3]] if v else [0]
        return norm(v1) < norm(v2)
    except Exception:
        return False


def _check_packages(packages: Dict[str, str]) -> List[Finding]:
    findings: List[Finding] = []
    for (pkg, max_safe, cve, severity, description, cvss) in VULNERABLE_PACKAGES:
        if pkg in packages:
            detected_ver = packages[pkg]
            # Clean version string (remove ^, ~, >=, etc.)
            clean_ver = re.sub(r"[^\d.]", "", detected_ver.split("-")[0])
            if clean_ver and _version_less_than(clean_ver, max_safe):
                findings.append(Finding(
                    title=f"Vulnerable Dependency: {pkg}@{detected_ver} ({cve})",
                    severity=severity,
                    description=description,
                    evidence=(
                        f"Package: {pkg}\n"
                        f"Detected version: {detected_ver}\n"
                        f"Safe version: >= {max_safe}\n"
                        f"CVE: {cve}\n"
                        f"CVSS: {cvss}"
                    ),
                    remediation=f"Upgrade {pkg} to version {max_safe} or later.",
                    code_fix=(
                        f"# pip:\npip install '{pkg}>={max_safe}'\n\n"
                        f"# npm:\nnpm install {pkg}@latest\n\n"
                        f"# yarn:\nyarn upgrade {pkg}"
                    ),
                    reference=f"https://nvd.nist.gov/vuln/detail/{cve}",
                    cvss=cvss,
                ))
    return findings


def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    base = url.rstrip("/")

    dep_files = [
        ("/package.json",      "npm"),
        ("/requirements.txt",  "pip"),
        ("/Pipfile",           "pipenv"),
    ]

    with get_client(timeout=timeout) as client:
        for (path, kind) in dep_files:
            try:
                resp = client.get(base + path)
                if resp.status_code != 200 or len(resp.text.strip()) < 10:
                    continue

                packages: Dict[str, str] = {}

                if kind == "npm":
                    try:
                        data = resp.json()
                        deps = {}
                        deps.update(data.get("dependencies", {}))
                        deps.update(data.get("devDependencies", {}))
                        packages = {k.lower(): v for k, v in deps.items()}
                    except Exception:
                        continue

                elif kind in ("pip", "pipenv"):
                    for line in resp.text.splitlines():
                        line = line.strip()
                        if line.startswith("#") or not line:
                            continue
                        match = re.match(r"^([a-zA-Z0-9_\-]+)\s*[>=<!=]+\s*([\d.]+)", line)
                        if match:
                            packages[match.group(1).lower()] = match.group(2)

                if packages:
                    findings.append(Finding(
                        title=f"Dependency File Accessible: {path}",
                        severity=Severity.INFO,
                        description=(
                            f"Found {len(packages)} packages in {path}. "
                            "Checking for known vulnerable versions..."
                        ),
                        evidence=f"HTTP 200 at {base+path}",
                        remediation="Consider blocking public access to dependency files.",
                        code_fix=f"location ~ /{path.lstrip('/')} {{ deny all; }}",
                    ))
                    vuln_findings = _check_packages(packages)
                    findings.extend(vuln_findings)

            except Exception:
                continue

    return findings
