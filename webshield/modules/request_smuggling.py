"""
HTTP Request Smuggling Detection Module (v1.8.0)
Detects CL.TE and TE.CL desync vulnerabilities.

Termux/Android: raw socket fallback — tries httpx first (safer),
falls back to raw socket only on PC/Linux with root or allowed ports.
"""
from __future__ import annotations
import time
import socket
import ssl
from typing import List
from urllib.parse import urlparse
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client, is_android

# CL.TE payload — Content-Length says body is 13 bytes,
# but Transfer-Encoding: chunked says it ends at 0 chunk
CLTE_PAYLOAD = (
    "POST / HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: 35\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    "0\r\n"
    "\r\n"
    "GET /webshield-smuggle-probe HTTP/1.1\r\n"
    "X-Ignore: X"
)

TECL_PAYLOAD = (
    "POST / HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: 4\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    "5c\r\n"
    "GPOST / HTTP/1.1\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: 15\r\n"
    "\r\n"
    "x=1\r\n"
    "0\r\n"
    "\r\n"
)

# TE obfuscation payloads (WAF bypass)
TE_OBFUSCATION_PAYLOADS = [
    "Transfer-Encoding: xchunked\r\n",
    "Transfer-Encoding :\r\nchunked\r\n",
    "Transfer-Encoding: chunked\r\nTransfer-Encoding: x\r\n",
    "Transfer-Encoding: chunked\r\n Transfer-Encoding: x\r\n",
]

SMUGGLE_INDICATORS = [
    b"webshield-smuggle-probe",
    b"GPOST",
    b"400 Bad Request",
    b"Invalid request",
    b"Unrecognized method",
]


def _raw_socket_probe(host: str, port: int, payload: str, use_ssl: bool, timeout: float) -> bytes:
    """Send raw HTTP payload via socket. Returns response bytes or empty on error."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)

        sock.settimeout(timeout)
        sock.sendall(payload.encode("utf-8", errors="replace"))

        response = b""
        start = time.time()
        while time.time() - start < timeout:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if b"\r\n\r\n" in response:
                    break
            except (socket.timeout, OSError):
                break
        sock.close()
        return response
    except Exception:
        return b""


def _httpx_timing_probe(url: str, timeout: float) -> tuple:
    """
    Timing-based smuggling probe using httpx.
    Send two identical requests — if second is significantly faster (cached smuggle),
    it may indicate CL.TE vulnerability.
    Returns (timing_diff_seconds, response_diff_detected)
    """
    try:
        with get_client(timeout=timeout) as client:
            # Baseline request
            t1 = time.time()
            r1 = client.post(url, content=b"param=value",
                             headers={"Content-Type": "application/x-www-form-urlencoded"})
            t1_elapsed = time.time() - t1

            # Probe request with TE header obfuscation
            t2 = time.time()
            r2 = client.post(url, content=b"param=value",
                             headers={
                                 "Content-Type": "application/x-www-form-urlencoded",
                                 "Transfer-Encoding": "chunked",
                                 "Content-Length": "11",
                             })
            t2_elapsed = time.time() - t2

            status_diff = r1.status_code != r2.status_code
            timing_diff = abs(t1_elapsed - t2_elapsed)
            return timing_diff, status_diff, r1.status_code, r2.status_code
    except Exception:
        return 0.0, False, 0, 0


def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    parsed   = urlparse(url)
    host     = parsed.hostname or ""
    port     = parsed.port or (443 if parsed.scheme == "https" else 80)
    use_ssl  = parsed.scheme == "https"
    safe_timeout = min(timeout, 6.0)

    # On Android/Termux, raw socket to ports 80/443 may be blocked.
    # Use httpx timing probe instead (less accurate but works everywhere).
    if is_android():
        timing_diff, status_diff, s1, s2 = _httpx_timing_probe(url, safe_timeout)
        if status_diff and s1 != 0 and s2 != 0:
            findings.append(Finding(
                title="HTTP Request Smuggling — Differential Response Detected",
                severity=Severity.HIGH,
                description=(
                    "Requests with Transfer-Encoding: chunked produced different HTTP status "
                    "codes compared to baseline requests. This may indicate HTTP request "
                    "smuggling vulnerability (CL.TE or TE.CL desync)."
                ),
                evidence=(
                    f"Baseline POST → HTTP {s1}\n"
                    f"TE: chunked POST → HTTP {s2}\n"
                    f"(Android/Termux mode — timing probe used)"
                ),
                remediation=(
                    "Ensure both frontend and backend agree on Transfer-Encoding handling. "
                    "Disable TE: chunked if not needed. Use HTTP/2 end-to-end."
                ),
                code_fix=(
                    "# Nginx — disable chunked encoding inconsistencies:\n"
                    "chunked_transfer_encoding off;\n\n"
                    "# Or normalise at the proxy layer:\n"
                    "proxy_http_version 1.1;\n"
                    "proxy_set_header Connection '';"
                ),
                reference="https://portswigger.net/web-security/request-smuggling",
                module="request_smuggling",
                cvss=8.1,
            ))
        return findings

    # Full raw socket probe (PC/Linux)
    for (name, payload_template) in [("CL.TE", CLTE_PAYLOAD), ("TE.CL", TECL_PAYLOAD)]:
        payload = payload_template.format(host=host)
        try:
            t_before = time.time()
            response = _raw_socket_probe(host, port, payload, use_ssl, safe_timeout)
            elapsed = time.time() - t_before

            if not response:
                continue

            indicator_hit = any(ind in response for ind in SMUGGLE_INDICATORS)
            timeout_hit = elapsed >= safe_timeout * 0.9

            if indicator_hit or timeout_hit:
                findings.append(Finding(
                    title=f"HTTP Request Smuggling ({name}) Detected",
                    severity=Severity.HIGH,
                    description=(
                        f"Potential HTTP Request Smuggling ({name}) detected. "
                        "Front-end and back-end servers disagree on request boundaries. "
                        "Attackers can bypass security controls, hijack requests, and "
                        "perform cache poisoning attacks."
                    ),
                    evidence=(
                        f"Type: {name}\n"
                        f"Response time: {elapsed:.2f}s\n"
                        f"Indicator: {'content match' if indicator_hit else 'timeout (blind)'}\n"
                        f"Response snippet: {response[:150]}"
                    ),
                    remediation=(
                        "Disable Transfer-Encoding on backend servers. "
                        "Use HTTP/2 end-to-end (eliminates CL/TE ambiguity). "
                        "Reject requests with both Content-Length and Transfer-Encoding."
                    ),
                    code_fix=(
                        "# Nginx — reject ambiguous requests:\n"
                        "if ($http_transfer_encoding ~* 'chunked') {\n"
                        "    return 400;\n"
                        "}\n\n"
                        "# HAProxy:\n"
                        "option http-server-close\n"
                        "option forwardfor"
                    ),
                    reference="https://portswigger.net/web-security/request-smuggling",
                    module="request_smuggling",
                    cvss=8.1,
                ))
                break
        except Exception:
            continue

    return findings
