"""
HTTP Request Smuggling Detection Module
Detects CL.TE and TE.CL desync vulnerabilities using timing.
Learned from: GSEC (request_smuggling.py — raw socket approach, best implementation found)
"""

from __future__ import annotations
import socket
import ssl
import time
from typing import List
from urllib.parse import urlparse
from webshield.core.models import Finding, Severity


def _send_raw(hostname: str, port: int, use_ssl: bool,
              payload: bytes, timeout: float = 8.0) -> float:
    """Send raw bytes and return response time."""
    start = time.perf_counter()
    try:
        sock = socket.create_connection((hostname, port), timeout=timeout)
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=hostname)
        sock.settimeout(timeout)
        sock.sendall(payload)
        # Read response (up to 4KB)
        data = b""
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) > 4096:
                    break
        except socket.timeout:
            pass
        sock.close()
    except Exception:
        pass
    return time.perf_counter() - start


def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        return []
    use_ssl = parsed.scheme == "https"
    port = parsed.port or (443 if use_ssl else 80)
    path = parsed.path or "/"

    # ── CL.TE probe ─────────────────────────────────────────────────
    # Front-end uses Content-Length, back-end uses Transfer-Encoding
    # If vulnerable, the 'G' gets prepended to next request, causing timeout
    cl_te_payload = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {hostname}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 6\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
        "0\r\n"
        "\r\n"
        "G"
    ).encode()

    # ── TE.CL probe ─────────────────────────────────────────────────
    te_cl_payload = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {hostname}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 3\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
        "1\r\n"
        "G\r\n"
        "0\r\n"
        "\r\n"
    ).encode()

    # Get baseline response time
    baseline_payload = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {hostname}\r\n"
        "Connection: close\r\n\r\n"
    ).encode()

    try:
        baseline = _send_raw(hostname, port, use_ssl, baseline_payload, timeout=5.0)

        # Test CL.TE
        t1 = _send_raw(hostname, port, use_ssl, cl_te_payload, timeout=timeout)
        if t1 > baseline * 3 and t1 > 4.0:
            findings.append(Finding(
                title="Possible HTTP Request Smuggling (CL.TE)",
                severity=Severity.HIGH,
                description=(
                    "A timing anomaly suggests CL.TE request smuggling may be possible. "
                    "The front-end uses Content-Length while the back-end uses "
                    "Transfer-Encoding. Attackers can poison the back-end TCP stream, "
                    "hijack other users' requests, and bypass security controls."
                ),
                evidence=(
                    f"Baseline response time: {baseline:.2f}s\n"
                    f"CL.TE probe response time: {t1:.2f}s\n"
                    f"Ratio: {t1/max(baseline,0.01):.1f}x (threshold: 3x)"
                ),
                remediation=(
                    "Ensure front-end and back-end servers use the same method "
                    "for determining request boundaries. Reject requests with both "
                    "Content-Length and Transfer-Encoding headers."
                ),
                code_fix=(
                    "# Nginx — reject ambiguous requests:\n"
                    "# Ensure upstream servers normalize Transfer-Encoding\n\n"
                    "# HAProxy:\n"
                    "option http-server-close\n"
                    "option forwardfor"
                ),
                reference="https://portswigger.net/web-security/request-smuggling",
                cvss=8.1,
            ))

        # Test TE.CL
        t2 = _send_raw(hostname, port, use_ssl, te_cl_payload, timeout=timeout)
        if t2 > baseline * 3 and t2 > 4.0:
            findings.append(Finding(
                title="Possible HTTP Request Smuggling (TE.CL)",
                severity=Severity.HIGH,
                description=(
                    "A timing anomaly suggests TE.CL request smuggling may be possible. "
                    "The front-end uses Transfer-Encoding while the back-end uses "
                    "Content-Length."
                ),
                evidence=(
                    f"Baseline: {baseline:.2f}s\n"
                    f"TE.CL probe: {t2:.2f}s\n"
                    f"Ratio: {t2/max(baseline,0.01):.1f}x"
                ),
                remediation=(
                    "Normalize all HTTP requests at the reverse proxy layer. "
                    "Disable HTTP/1.1 keep-alive or use HTTP/2 end-to-end."
                ),
                reference="https://portswigger.net/web-security/request-smuggling/lab-basic-te-cl",
                cvss=8.1,
            ))

    except Exception:
        pass

    return findings
