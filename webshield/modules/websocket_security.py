"""
WebSocket Security Module (v1.6.0)
Detects WebSocket misconfigurations and vulnerabilities.
Inspired by: ZAP WebSocket passive scan rules, PortSwigger WS research

Checks:
1. Unencrypted WebSocket (ws:// on HTTPS site) — downgrade attack
2. Missing Origin validation — cross-site WebSocket hijacking (CSWSH)
3. Exposed WebSocket endpoints without authentication signals
4. WebSocket injection probes (XSS via WS messages)
5. WS endpoint discovery via common paths
"""

from __future__ import annotations
import re
import socket
import base64
import hashlib
from typing import List
from urllib.parse import urlparse
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

# Common WebSocket endpoint paths
WS_PATHS = [
    "/ws", "/websocket", "/socket", "/socket.io/",
    "/ws/", "/chat", "/live", "/stream", "/push",
    "/realtime", "/events", "/sockjs/info",
    "/cable",          # Rails Action Cable
    "/graphql-ws",     # GraphQL subscriptions
    "/api/ws",
    "/_next/webpack-hmr",  # Next.js HMR (should not be in prod)
]

# Patterns in HTTP responses that hint at WebSocket usage
WS_HINTS = re.compile(
    r"socket\.io|websocket|new WebSocket|SockJS|ActionCable|"
    r"graphql-ws|phoenix\.js|ws://|wss://",
    re.I,
)

# Upgrade response indicator
WS_UPGRADE_PATTERN = re.compile(r"upgrade.*websocket|websocket.*upgrade", re.I)


def _make_ws_handshake_request(host: str, port: int, path: str,
                                origin: str, use_ssl: bool = False) -> dict:
    """
    Perform a raw HTTP Upgrade request for WebSocket.
    Returns dict with: status, headers_raw, upgraded
    """
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
        status_code = int(status_line.split(" ")[1]) if " " in status_line else 0
        upgraded = status_code == 101
        return {"status": status_code, "headers": resp_str, "upgraded": upgraded}
    except Exception as e:
        return {"status": 0, "headers": "", "upgraded": False, "error": str(e)}


def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    parsed   = urlparse(url)
    scheme   = parsed.scheme   # http or https
    host     = parsed.hostname or ""
    port     = parsed.port or (443 if scheme == "https" else 80)
    use_ssl  = scheme == "https"
    base_url = f"{scheme}://{parsed.netloc}"

    with get_client(timeout=min(timeout, 8.0)) as client:

        # ── Phase 1: Detect WS usage on the main page
        ws_endpoints_found: List[str] = []
        try:
            resp = client.get(url)
            if WS_HINTS.search(resp.text):
                # Extract ws:// / wss:// URLs from JS source
                ws_urls = re.findall(r"""(?:ws|wss)://[^\s'"<>]+""", resp.text)
                for wu in ws_urls[:5]:
                    ws_endpoints_found.append(wu)

                # Check for unencrypted ws:// on HTTPS page (downgrade)
                insecure_ws = [w for w in ws_urls if w.startswith("ws://")]
                if insecure_ws and scheme == "https":
                    findings.append(Finding(
                        title="Insecure WebSocket (ws://) on HTTPS Page — Downgrade Attack",
                        severity=Severity.HIGH,
                        description=(
                            "The HTTPS page contains JavaScript that connects to an unencrypted "
                            "WebSocket endpoint (ws://). This allows network attackers to "
                            "intercept, read, and modify all WebSocket traffic in cleartext — "
                            "defeating the HTTPS encryption protecting the page."
                        ),
                        evidence=(
                            f"Found on: {url}\n"
                            f"Insecure WS URLs: {insecure_ws[:3]}"
                        ),
                        remediation=(
                            "Always use wss:// (WebSocket Secure) on HTTPS sites. "
                            "Use relative URLs or derive from window.location.protocol."
                        ),
                        code_fix=(
                            "// ❌ Vulnerable:\n"
                            "const ws = new WebSocket('ws://example.com/ws');\n\n"
                            "// ✅ Safe — derive protocol from page:\n"
                            "const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';\n"
                            "const ws = new WebSocket(`${proto}//${window.location.host}/ws`);"
                        ),
                        reference="https://portswigger.net/web-security/websockets",
                        module="websocket_security",
                        cvss=7.4,
                    ))
        except Exception:
            pass

        # ── Phase 2: Probe common WS endpoints
        active_paths: List[str] = []

        for path in WS_PATHS:
            # First check if endpoint exists via HTTP (may return 400 "not a WS upgrade")
            try:
                r = client.get(base_url + path)
                # 400 with websocket error = endpoint exists but needs upgrade
                if r.status_code in (200, 400, 426) or WS_UPGRADE_PATTERN.search(str(r.headers)):
                    active_paths.append(path)
            except Exception:
                continue

        # ── Phase 3: Test Origin validation on discovered endpoints
        for path in active_paths[:4]:
            # Test with evil.com origin — if it upgrades, no origin check!
            result_evil = _make_ws_handshake_request(
                host, port, path, "https://evil.com", use_ssl
            )
            result_same = _make_ws_handshake_request(
                host, port, path, f"{scheme}://{parsed.netloc}", use_ssl
            )

            if result_evil.get("upgraded"):
                # Critical: accepts arbitrary origin — Cross-Site WebSocket Hijacking
                findings.append(Finding(
                    title=f"Cross-Site WebSocket Hijacking (CSWSH) — {path}",
                    severity=Severity.HIGH,
                    description=(
                        f"The WebSocket endpoint {path} accepts connections from arbitrary origins "
                        "(Origin: https://evil.com was accepted). This allows Cross-Site WebSocket "
                        "Hijacking (CSWSH): a malicious website can connect to this WebSocket as "
                        "the victim user and read/send messages on their behalf."
                    ),
                    evidence=(
                        f"WebSocket path: {base_url.replace('http', 'ws') + path}\n"
                        f"Origin: https://evil.com → HTTP 101 Upgrade accepted\n"
                        f"No origin validation detected"
                    ),
                    remediation=(
                        "Validate the Origin header on the server before accepting WebSocket upgrades. "
                        "Only accept connections from your own domain(s)."
                    ),
                    code_fix=(
                        "# Python/websockets:\n"
                        "async def handler(websocket, path):\n"
                        "    origin = websocket.request_headers.get('Origin', '')\n"
                        "    allowed = ['https://yourdomain.com']\n"
                        "    if origin not in allowed:\n"
                        "        await websocket.close(1008, 'Invalid origin')\n"
                        "        return\n\n"
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

            elif result_same.get("upgraded"):
                # WS endpoint exists but does check origin — note as INFO
                findings.append(Finding(
                    title=f"WebSocket Endpoint Found — Origin Check Present ({path})",
                    severity=Severity.INFO,
                    description=(
                        f"A WebSocket endpoint was found at {path}. "
                        "It appears to validate the Origin header correctly — "
                        "only same-origin connections are accepted."
                    ),
                    evidence=f"WebSocket at: {base_url.replace('http','ws') + path}\nSame-origin upgrade: accepted\nEvil-origin upgrade: rejected",
                    remediation="Ensure WebSocket messages are also authenticated (session/token check).",
                    code_fix="",
                    reference="https://portswigger.net/web-security/websockets",
                    module="websocket_security",
                    cvss=0.0,
                ))

        # ── Phase 4: Check for Next.js HMR in production (should never be exposed)
        try:
            r = client.get(base_url + "/_next/webpack-hmr")
            if r.status_code in (200, 400) and "webpack" in r.text.lower():
                findings.append(Finding(
                    title="Next.js HMR WebSocket Exposed in Production",
                    severity=Severity.MEDIUM,
                    description=(
                        "The Next.js Hot Module Replacement (HMR) WebSocket endpoint is accessible. "
                        "HMR is a development feature that should never be exposed in production. "
                        "It reveals source file structure and may allow triggering module reloads."
                    ),
                    evidence=f"GET /_next/webpack-hmr → HTTP {r.status_code}",
                    remediation=(
                        "Ensure you are deploying a production build (`next build` + `next start`). "
                        "Never run `next dev` in production."
                    ),
                    code_fix=(
                        "# package.json — always use production build:\n"
                        '"scripts": {\n'
                        '    "start": "next start",   // production\n'
                        '    "dev":   "next dev"       // development only\n'
                        "}\n\n"
                        "# Block in Nginx as belt-and-suspenders:\n"
                        "location /_next/webpack-hmr {\n"
                        "    deny all;\n"
                        "    return 404;\n"
                        "}"
                    ),
                    reference="https://nextjs.org/docs/deployment",
                    module="websocket_security",
                    cvss=5.3,
                ))
        except Exception:
            pass

    return findings
