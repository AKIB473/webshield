"""
SSL/TLS Module
Checks certificate validity, expiry, protocol versions, weak ciphers.
Learned from: yawast-ng (SSLyze), Nettacker (yaml ssl module), Wapiti (mod_ssl)
"""

from __future__ import annotations
import ssl
import socket
import datetime
from typing import List, Tuple, Optional
from urllib.parse import urlparse
from webshield.core.models import Finding, Severity

WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
WEAK_CIPHERS_KEYWORDS = [
    "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT",
    "anon", "ADH", "AECDH", "PSK", "SRP",
]


def _get_cert_info(hostname: str, port: int = 443, timeout: float = 10.0) -> Tuple[Optional[dict], Optional[str]]:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                protocol = ssock.version()
                return {"cert": cert, "cipher": cipher, "protocol": protocol}, None
    except ssl.SSLError as e:
        return None, f"SSL error: {e}"
    except socket.timeout:
        return None, "Connection timed out"
    except ConnectionRefusedError:
        return None, "Connection refused (port not open)"
    except Exception as e:
        return None, str(e)


def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    parsed = urlparse(url)

    if parsed.scheme != "https":
        findings.append(Finding(
            title="Site Not Using HTTPS",
            severity=Severity.CRITICAL,
            description=(
                "Your site is served over plain HTTP. All traffic is unencrypted and "
                "visible to anyone on the network. Passwords, session cookies, and form "
                "data are all exposed."
            ),
            evidence=f"URL scheme is '{parsed.scheme}', not 'https'",
            remediation=(
                "Obtain a TLS certificate (free via Let's Encrypt) and redirect all "
                "HTTP traffic to HTTPS. This is non-negotiable for any public website."
            ),
            code_fix=(
                "# Nginx:\n"
                "server {\n"
                "    listen 80;\n"
                "    return 301 https://$host$request_uri;\n"
                "}\n\n"
                "# Certbot (Let's Encrypt):\n"
                "certbot --nginx -d yourdomain.com"
            ),
            reference="https://letsencrypt.org/getting-started/",
            cvss=9.1,
        ))
        return findings

    hostname = parsed.hostname
    port = parsed.port or 443

    ssl_info, error = _get_cert_info(hostname, port, timeout)

    if error:
        findings.append(Finding(
            title="SSL/TLS Connection Failed",
            severity=Severity.HIGH,
            description=f"Could not establish SSL/TLS connection: {error}",
            evidence=error,
            remediation="Ensure your SSL certificate is valid and the server is reachable.",
            reference="https://www.ssllabs.com/ssltest/",
        ))
        return findings

    cert = ssl_info["cert"]
    cipher_name, protocol, bits = ssl_info["cipher"]
    protocol_ver = ssl_info["protocol"]

    # 1. Expired certificate
    if cert and "notAfter" in cert:
        try:
            expiry = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            now = datetime.datetime.utcnow()
            days_left = (expiry - now).days

            if days_left < 0:
                findings.append(Finding(
                    title="SSL Certificate Has Expired",
                    severity=Severity.CRITICAL,
                    description=(
                        f"Your SSL certificate expired {abs(days_left)} days ago. "
                        "Browsers will show security warnings and refuse connections."
                    ),
                    evidence=f"Certificate expired on: {expiry.strftime('%Y-%m-%d')}",
                    remediation="Renew your SSL certificate immediately using Let's Encrypt or your CA.",
                    code_fix="certbot renew --force-renewal",
                    reference="https://letsencrypt.org/docs/renewing-certs/",
                    cvss=9.0,
                ))
            elif days_left < 14:
                findings.append(Finding(
                    title=f"SSL Certificate Expiring Soon ({days_left} days)",
                    severity=Severity.HIGH,
                    description=(
                        f"Your SSL certificate expires in {days_left} days. "
                        "If not renewed, browsers will block access to your site."
                    ),
                    evidence=f"Expiry date: {expiry.strftime('%Y-%m-%d')}",
                    remediation="Renew your SSL certificate now to avoid service interruption.",
                    code_fix="certbot renew",
                    reference="https://letsencrypt.org/docs/renewing-certs/",
                    cvss=6.0,
                ))
            elif days_left < 30:
                findings.append(Finding(
                    title=f"SSL Certificate Expiring in {days_left} Days",
                    severity=Severity.MEDIUM,
                    description="Certificate renewal recommended within the next 30 days.",
                    evidence=f"Expiry date: {expiry.strftime('%Y-%m-%d')}",
                    remediation="Schedule certificate renewal.",
                    code_fix="certbot renew",
                    reference="https://letsencrypt.org/docs/renewing-certs/",
                ))
        except Exception:
            pass

    # 2. Self-signed certificate
    if cert:
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer  = dict(x[0] for x in cert.get("issuer",  []))
        if subject == issuer:
            findings.append(Finding(
                title="Self-Signed SSL Certificate",
                severity=Severity.HIGH,
                description=(
                    "The SSL certificate is self-signed, meaning it was not issued by a "
                    "trusted Certificate Authority. Browsers will show a security warning."
                ),
                evidence=f"Issuer == Subject: {issuer.get('commonName', 'Unknown')}",
                remediation="Replace the self-signed certificate with one from Let's Encrypt (free) or a trusted CA.",
                code_fix="certbot --nginx -d yourdomain.com",
                reference="https://letsencrypt.org/",
                cvss=6.5,
            ))

    # 3. Weak protocol
    if protocol_ver in WEAK_PROTOCOLS:
        findings.append(Finding(
            title=f"Weak TLS Protocol in Use: {protocol_ver}",
            severity=Severity.HIGH,
            description=(
                f"The server negotiated {protocol_ver}, which is deprecated and vulnerable "
                "to known attacks (POODLE, BEAST, etc.). Only TLSv1.2+ should be accepted."
            ),
            evidence=f"Negotiated protocol: {protocol_ver}",
            remediation="Disable TLS 1.0 and 1.1 in your server config. Require TLS 1.2 minimum.",
            code_fix=(
                "# Nginx:\n"
                "ssl_protocols TLSv1.2 TLSv1.3;\n\n"
                "# Apache:\n"
                "SSLProtocol -all +TLSv1.2 +TLSv1.3"
            ),
            reference="https://www.rfc-editor.org/rfc/rfc8996",
            cvss=7.5,
        ))

    # 4. Weak cipher
    for weak_kw in WEAK_CIPHERS_KEYWORDS:
        if weak_kw.upper() in cipher_name.upper():
            findings.append(Finding(
                title=f"Weak Cipher Suite in Use: {cipher_name}",
                severity=Severity.HIGH,
                description=(
                    f"The negotiated cipher '{cipher_name}' contains '{weak_kw}' which is "
                    "considered cryptographically weak. Attackers may decrypt traffic."
                ),
                evidence=f"Cipher: {cipher_name}, Protocol: {protocol_ver}, Bits: {bits}",
                remediation="Configure your server to only accept strong cipher suites.",
                code_fix=(
                    "# Nginx:\n"
                    "ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"
                    ":ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;\n"
                    "ssl_prefer_server_ciphers off;"
                ),
                reference="https://wiki.mozilla.org/Security/Server_Side_TLS",
                cvss=7.0,
            ))
            break

    # 5. Weak key size
    if bits and bits < 128:
        findings.append(Finding(
            title=f"Weak Encryption Key Size: {bits} bits",
            severity=Severity.HIGH,
            description=f"The negotiated cipher uses only {bits}-bit encryption, which is insufficient.",
            evidence=f"Cipher: {cipher_name}, Bits: {bits}",
            remediation="Use ciphers with at least 128-bit key sizes (AES-128-GCM or AES-256-GCM).",
            reference="https://wiki.mozilla.org/Security/Server_Side_TLS",
            cvss=6.5,
        ))

    # All good info
    if not findings:
        findings.append(Finding(
            title="SSL/TLS Configuration Looks Good",
            severity=Severity.INFO,
            description=f"Protocol: {protocol_ver} | Cipher: {cipher_name} | Key: {bits} bits",
            evidence=f"No SSL/TLS issues detected for {hostname}",
        ))

    return findings
