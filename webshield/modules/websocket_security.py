"""
WebSocket Security Module (v1.8.1)
Detects WebSocket misconfigurations and vulnerabilities.

Termux/Android: raw socket may be blocked — graceful fallback to HTTP-only checks.
"""
from __future__ import annotations
import re
import socket
import base64
import hashlib
from typing import List
from urllib.parse import urlparse
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client, is_android

WS_PATHS = [
    "/ws", "/websocket", "/socket", "/socket.io/",
    "/ws/", "/chat", "/live", "/stream", "/push",
    "/realtime", "/events", "/sockjs/info",
    "/cable", "/graphql-ws", "/api/ws",
    "/_next/webpack-hmr",
]

WS_HINTS = re.compile(
    r"socket\.io|websocket|new WebSocket|SockJS|ActionCable|"
    r"graphql-ws|phoenix\.js|ws://|wss://",
    re.I,
)
WS_UPGRADE_PATTERN = re.compile(r"upgrade.*websocket|websocket.*upgrade", re.I)


def _make_ws_handshake_request(
    host: str, port: int, path: str, origin: str, use_ssl: bool = False
) -> dict:
    """Perform raw HTTP Upgrade. Returns dict with status, headers, upgraded."""
    # Skip raw socket on Android — ports often blocked
    if is_android():
        return {"status": 0, "headers": "", "upgraded": False, "skipped": True}

    key = base64.b64encode(b"webshield-probe-key-1234").decode()
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        f"Origin: {origin}\r\n"
        "\r\n"
    )
    try:
        sock = socket.create_connection((host, port), timeout=5)
        if use_ssl:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)

        sock.sendall(request.encode())
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = sock.recv(1024)
            if not chunk:
                break
            response += chunk
        sock.close()
        resp_str = response.decode("utf-8", errors="replace")
        status_line = resp_str.split("\r\n")[0]
        status_code = int(status_line.split(" ")[1]) if len(status_line.split(" ")) > 1 else 0
        return {"status": status_code, "headers": resp_str, "upgraded": status_code == 101}
    except Exception as e:
        return {"status": 0, "headers": "", "upgraded": False, "error": str(e)}


def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    parsed   = urlparse(url)
    scheme   = parsed.scheme
    host     = parsed.hostname or ""
    port     = parsed.port or (443 if scheme == "https" else 80)
    use_ssl  = scheme == "https"
    base_url = f"{scheme}://{parsed.netloc}"

    with get_client(timeout=min(timeout, 8.0)) as client:

        # ── 1. Detect WS usage on the main page
        try:
            resp = client.get(url)
            if WS_HINTS.search(resp.text):
                ws_urls = re.findall(r"""(?:ws|wss)://[^\s'"<>]+""", resp.text)

                insecure_ws = [w for w in ws_urls if w.startswith("ws://")]
                if insecure_ws and scheme == "https":
                    findings.append(Finding(
                        title="Insecure WebSocket (ws://) on HTTPS Page — Downgrade Attack",
                        severity=Severity.HIGH,
                        description=(
                            "The HTTPS page contains JavaScript that connects to an unencrypted "
                            "WebSocket (ws://). Network attackers can intercept, read, and modify "
                            "all WebSocket messages in cleartext, defeating HTTPS protection."
                        ),
                        evidence=f"Insecure WS URLs found: {insecure_ws[:3]}",
                        remediation="Always use wss:// on HTTPS pages. Derive from window.location.protocol.",
                        code_fix=(
                            "// ❌ Vulnerable:\nconst ws = new WebSocket('ws://example.com/ws');\n\n"
                            "// ✅ Safe:\n"
                            "const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';\n"
                            "const ws = new WebSocket(`${proto}//${window.location.host}/ws`);"
                        ),
                        reference="https://portswigger.net/web-security/websockets",
                        module="websocket_security",
                        cvss=7.4,
                    ))
        except Exception:
            pass

        # ── 2. Probe common WS endpoints via HTTP (check for 400/426 = endpoint exists)
        active_paths: List[str] = []
        for path in WS_PATHS:
            try:
                r = client.get(base_url + path)
                if r.status_code in (200, 400, 426) or WS_UPGRADE_PATTERN.search(str(r.headers)):
                    active_paths.append(path)
            except Exception:
                continue

        # ── 3. Test Origin validation (raw socket — skipped on Android)
        if not is_android():
            for path in active_paths[:4]:
                result_evil = _make_ws_handshake_request(
                    host, port, path, "https://evil.com", use_ssl
                )
                if result_evil.get("upgraded"):
                    findings.append(Finding(
                        title=f"Cross-Site WebSocket Hijacking (CSWSH) — {path}",
                        severity=Severity.HIGH,
                        description=(
                            f"The WebSocket endpoint {path} accepts connections from arbitrary origins "
                            "(Origin: https://evil.com accepted). Attackers can connect as victim users "
                            "and read/send WebSocket messages on their behalf."
                        ),
                        evidence=(
                            f"WebSocket: {base_url.replace('http','ws') + path}\n"
                            "Origin: https://evil.com → HTTP 101 Upgrade accepted"
                        ),
                        remediation="Validate Origin header before accepting WebSocket upgrades.",
                        code_fix=(
                            "# Node.js/ws:\n"
                            "const wss = new WebSocket.Server({\n"
                            "    verifyClient: ({ origin }) =>\n"
                            "        ['https://yourdomain.com'].includes(origin)\n"
                            "});"
                        ),
                        reference="https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking",
                        module="websocket_security",
                        cvss=8.1,
                    ))
        else:
            # Android: inform about WS endpoints found but can't test origin
            if active_paths:
                findings.append(Finding(
                    title=f"WebSocket Endpoints Found — Manual Origin Test Needed ({len(active_paths)} paths)",
                    severity=Severity.INFO,
                    description=(
                        f"WebSocket endpoint(s) found: {active_paths[:3]}. "
                        "Cross-site WebSocket hijacking (origin validation) test requires "
                        "raw socket access — run on a PC for full testing."
                    ),
                    evidence=f"Paths: {active_paths[:3]}",
                    remediation="Test CSWSH manually or re-run on PC/Linux for full analysis.",
                    code_fix="",
                    reference="https://portswigger.net/web-security/websockets",
                    module="websocket_security",
                    cvss=0.0,
                ))

        # ── 4. Next.js HMR in production
        try:
            r = client.get(base_url + "/_next/webpack-hmr")
            if r.status_code in (200, 400) and "webpack" in r.text.lower():
                findings.append(Finding(
                    title="Next.js HMR WebSocket Exposed in Production",
                    severity=Severity.MEDIUM,
                    description=(
                        "Next.js Hot Module Replacement WebSocket is accessible. "
                        "HMR is a development feature revealing source structure and module paths."
                    ),
                    evidence=f"GET /_next/webpack-hmr → HTTP {r.status_code}",
                    remediation="Use `next build` + `next start` in production, never `next dev`.",
                    code_fix=(
                        "# Nginx:\nlocation /_next/webpack-hmr {\n    deny all;\n    return 404;\n}"
                    ),
                    reference="https://nextjs.org/docs/deployment",
                    module="websocket_security",
                    cvss=5.3,
                ))
        except Exception:
            pass

    return findings
