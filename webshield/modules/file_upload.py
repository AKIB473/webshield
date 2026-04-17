"""
File Upload Security Testing Module (v1.5.0)
OWASP A04:2025 - Insecure Design | CVSS up to 9.8 (RCE via webshell)

How attackers exploit file uploads:
  File upload vulnerabilities are among the highest-impact web bugs — often
  leading directly to Remote Code Execution via webshell upload.

  Attack vectors:
  1. MIME type bypass: Change Content-Type to image/jpeg but upload PHP/ASP shell
  2. Extension bypass: double extension (shell.php.jpg), null byte (shell.php%00.jpg)
  3. Magic bytes bypass: prepend valid image header to malicious script
  4. Path traversal: ../../../../var/www/html/shell.php as filename
  5. Archive bombs: zip files that decompress to huge sizes (zip bomb)
  6. SSRF via SVG: upload SVG with external entity/SSRF payload
  7. XXE via office docs: DOCX/XLSX files with XXE payloads
  8. Stored XSS via SVG: <script> in SVG uploaded as image
  9. Content-Type confusion: serving uploaded .html as text/html

  Detection approach (passive — no actual webshell upload):
  - Discover upload endpoints
  - Test for dangerous response headers (Content-Type of uploaded files)
  - Check if server serves uploaded files with dangerous MIME types
  - Look for upload directory exposure (dir listing)
  - Check for missing security restrictions

References:
  - PortSwigger: https://portswigger.net/web-security/file-upload
  - HackTricks: https://book.hacktricks.xyz/pentesting-web/file-upload
"""

from __future__ import annotations
import re
from typing import List
from urllib.parse import urlparse
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

# ─── Upload endpoint discovery ────────────────────────────────────────────────
UPLOAD_PATHS = [
    "/upload", "/api/upload", "/api/v1/upload", "/uploads",
    "/file-upload", "/files/upload", "/media/upload",
    "/image/upload", "/images/upload", "/avatar/upload",
    "/attachment/upload", "/document/upload",
    "/admin/upload", "/admin/media",
]

# Upload directories to check for listing/direct access
UPLOAD_DIRS = [
    "/uploads/", "/upload/", "/files/", "/media/",
    "/images/", "/static/uploads/", "/public/uploads/",
    "/assets/uploads/", "/content/uploads/",
    "/wp-content/uploads/",   # WordPress
    "/storage/", "/storage/app/public/",
]

# Dangerous MIME types that should never be served from upload dirs
DANGEROUS_MIME_TYPES = {
    "application/x-php", "application/php", "text/php",
    "application/x-httpd-php", "application/x-httpd-php3",
    "text/asp", "application/x-asp",
    "text/x-script.phyton", "text/x-python",
    "application/x-sh", "text/x-sh",
    "text/html",  # dangerous if served from upload dir
    "application/javascript", "text/javascript",
}

# Webshell indicator patterns in 200 responses from upload dirs
WEBSHELL_PATTERNS = [
    re.compile(r"<\?php", re.I),
    re.compile(r"eval\s*\(", re.I),
    re.compile(r"system\s*\(", re.I),
    re.compile(r"exec\s*\(", re.I),
    re.compile(r"passthru\s*\(", re.I),
    re.compile(r"shell_exec\s*\(", re.I),
    re.compile(r"<%.*%>", re.S),  # ASP
    re.compile(r"<jsp:", re.I),
]

# Headers that indicate poor upload security
MISSING_SECURITY_HEADERS = [
    "x-content-type-options",  # must be nosniff on upload dirs
    "content-security-policy",
]


def _check_upload_endpoint(client, url: str, path: str, findings: List[Finding]) -> None:
    """Discover upload endpoints and check for security issues."""
    target = url.rstrip("/") + path
    try:
        resp = client.get(target)
        if resp.status_code not in (200, 405, 403):
            return

        ct = resp.headers.get("content-type", "").lower()
        xct = resp.headers.get("x-content-type-options", "").lower()

        # Found an upload endpoint
        if resp.status_code in (200, 405):
            issues = []

            # Check for missing nosniff header
            if "nosniff" not in xct:
                issues.append("X-Content-Type-Options: nosniff missing")

            # Check if GET on upload endpoint returns file listing
            body = resp.text
            if resp.status_code == 200 and (
                "index of" in body.lower() or
                "<a href=" in body.lower() and ".php" in body.lower()
            ):
                findings.append(Finding(
                    title=f"Upload Directory Listing Exposed: {path}",
                    severity=Severity.HIGH,
                    description=(
                        f"The upload directory '{path}' has directory listing enabled "
                        "and appears to contain uploaded files. Attackers can:\n"
                        "• Browse all uploaded files\n"
                        "• Find and access uploaded webshells\n"
                        "• Harvest sensitive uploaded documents"
                    ),
                    evidence=f"Directory listing at {target}\n{body[:200]}",
                    remediation=(
                        "Disable directory listing on all upload directories. "
                        "Store uploads outside web root if possible. "
                        "Serve uploads via application controller, not directly."
                    ),
                    code_fix=(
                        "# Nginx — disable directory listing:\n"
                        "autoindex off;  # (this is default)\n\n"
                        "# Apache:\n"
                        "Options -Indexes\n\n"
                        "# Better: serve files through app controller:\n"
                        "@app.route('/files/<filename>')\n"
                        "@login_required\n"
                        "def serve_file(filename):\n"
                        "    return send_from_directory(UPLOAD_DIR, filename)"
                    ),
                    reference="https://portswigger.net/web-security/file-upload",
                    cvss=7.5,
                ))

            if issues:
                findings.append(Finding(
                    title=f"File Upload Endpoint Found — Missing Security Headers: {path}",
                    severity=Severity.MEDIUM,
                    description=(
                        f"A file upload endpoint was found at '{path}'. "
                        f"Security issues: {', '.join(issues)}. "
                        "Without X-Content-Type-Options: nosniff, browsers may "
                        "execute uploaded files by sniffing their content type."
                    ),
                    evidence=(
                        f"Endpoint: {target}\n"
                        f"HTTP {resp.status_code}\n"
                        f"Issues: {', '.join(issues)}"
                    ),
                    remediation=(
                        "Add X-Content-Type-Options: nosniff to all upload endpoint responses. "
                        "Validate file type by content (magic bytes), not just extension or MIME. "
                        "Store uploads outside web root."
                    ),
                    code_fix=(
                        "# Flask — serve upload responses with security headers:\n"
                        "@app.after_request\n"
                        "def add_security_headers(resp):\n"
                        "    resp.headers['X-Content-Type-Options'] = 'nosniff'\n"
                        "    return resp\n\n"
                        "# Validate by magic bytes, not MIME:\n"
                        "import imghdr\n"
                        "image_type = imghdr.what(file_stream)\n"
                        "if image_type not in ('jpeg', 'png', 'gif', 'webp'):\n"
                        "    raise ValueError('Not an allowed image type')"
                    ),
                    reference="https://portswigger.net/web-security/file-upload",
                    cvss=5.3,
                ))

    except Exception:
        pass


def _check_upload_dir_xss(client, url: str, path: str, findings: List[Finding]) -> None:
    """
    Check if upload directories serve files with dangerous Content-Types
    or contain SVG with script content (stored XSS vector).
    """
    target = url.rstrip("/") + path
    try:
        resp = client.get(target)
        if resp.status_code != 200:
            return

        ct = resp.headers.get("content-type", "").lower()
        xct = resp.headers.get("x-content-type-options", "").lower()
        body = resp.text

        # Check for webshell patterns
        for pattern in WEBSHELL_PATTERNS:
            if pattern.search(body):
                findings.append(Finding(
                    title=f"Possible Webshell in Upload Directory: {path}",
                    severity=Severity.CRITICAL,
                    description=(
                        f"A file in the upload directory '{path}' contains server-side "
                        "code patterns (PHP/ASP/JSP). This could be an uploaded webshell "
                        "giving attackers full server access."
                    ),
                    evidence=(
                        f"URL: {target}\n"
                        f"Pattern: {pattern.pattern}\n"
                        f"Snippet: {body[:200]}"
                    ),
                    remediation=(
                        "Remove the file immediately. "
                        "Audit all uploaded files. "
                        "Implement strict file type validation on upload. "
                        "Never execute files from upload directories. "
                        "Run files through antivirus scanning on upload."
                    ),
                    reference="https://portswigger.net/web-security/file-upload",
                    cvss=9.8,
                ))
                return

        # Check for SVG with embedded scripts (stored XSS)
        if "svg" in ct or path.endswith(".svg"):
            if re.search(r"<script", body, re.I) or re.search(r"on\w+=", body, re.I):
                findings.append(Finding(
                    title=f"SVG with Script Content in Upload Dir: {path}",
                    severity=Severity.HIGH,
                    description=(
                        "An SVG file in the upload directory contains JavaScript. "
                        "SVG files served with image/svg+xml MIME type can execute JavaScript "
                        "in the browser's security context of your domain — stored XSS."
                    ),
                    evidence=f"URL: {target}\n{body[:200]}",
                    remediation=(
                        "Sanitize SVG uploads (remove script/event handlers). "
                        "Serve SVG files with Content-Disposition: attachment. "
                        "Or re-encode to PNG/JPEG on server side."
                    ),
                    reference="https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-obfuscated-file-extension",
                    cvss=7.5,
                ))

        # Check dangerous MIME type being served
        for dangerous_mime in DANGEROUS_MIME_TYPES:
            if dangerous_mime in ct and "nosniff" not in xct:
                findings.append(Finding(
                    title=f"Dangerous MIME Type Served from Upload Dir: {ct}",
                    severity=Severity.HIGH,
                    description=(
                        f"The upload directory serves files with Content-Type: {ct}. "
                        "Without X-Content-Type-Options: nosniff, browsers may execute "
                        "this content. If users can upload files, this enables script execution."
                    ),
                    evidence=f"URL: {target}\nContent-Type: {ct}",
                    remediation=(
                        "1. Add X-Content-Type-Options: nosniff to all responses\n"
                        "2. Never serve uploaded .php/.asp/.html files directly\n"
                        "3. Rename uploads to random non-executable names (e.g. UUID.bin)\n"
                        "4. Block execution in upload directory via web server config"
                    ),
                    code_fix=(
                        "# Nginx — prevent PHP execution in uploads:\n"
                        "location ~* /uploads/.*\\.php$ {\n"
                        "    deny all;\n"
                        "}\n\n"
                        "# Or serve everything as application/octet-stream:\n"
                        "location /uploads/ {\n"
                        "    add_header Content-Type application/octet-stream;\n"
                        "    add_header Content-Disposition 'attachment';\n"
                        "    add_header X-Content-Type-Options nosniff;\n"
                        "}"
                    ),
                    reference="https://portswigger.net/web-security/file-upload",
                    cvss=7.5,
                ))
                break

    except Exception:
        pass


def scan(url: str, timeout: float = 12.0) -> List[Finding]:
    findings: List[Finding] = []
    base = url.rstrip("/")

    with get_client(timeout=min(timeout, 8.0)) as client:
        # 1. Check upload endpoints
        for path in UPLOAD_PATHS[:8]:
            _check_upload_endpoint(client, base, path, findings)
            if len(findings) >= 3:
                break

        # 2. Check upload directories
        for path in UPLOAD_DIRS[:6]:
            _check_upload_dir_xss(client, base, path, findings)
            if len(findings) >= 3:
                break

    return findings
