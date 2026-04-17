"""
Insecure Deserialization Detection Module (v1.4.0)
OWASP A08:2025 - Software or Data Integrity Failures

How attackers exploit deserialization:
  Applications that deserialize untrusted data can be exploited by crafting
  malicious payloads that execute arbitrary code during deserialization.

  Common targets:
  - PHP: unserialize() with O:8:"UserData"... — gadget chain attacks
  - Python: pickle.loads(), marshal.loads()
  - Java: ObjectInputStream — Apache Commons Collections gadget chains
  - Node.js: node-serialize, serialize-javascript
  - Ruby: Marshal.load
  - .NET: BinaryFormatter, XmlSerializer

  Famous exploits:
  - CVE-2015-4852 (WebLogic RCE via Java deserialization)
  - CVE-2017-5638 (Apache Struts2 — RCE via XStream)
  - CVE-2019-0604 (SharePoint deserialization RCE)

Detection approach:
  - Check for Java serialization magic bytes (0xACED) in cookies/params
  - Look for PHP serialize() patterns in URLs/cookies
  - Test for error messages that reveal deserialization internals
  - Check for ViewState in .NET apps (often unprotected)
"""

from __future__ import annotations
import base64
import re
from typing import List
from urllib.parse import urlparse
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

# Java serialization magic bytes: 0xAC 0xED 0x00 0x05
JAVA_SERIAL_MAGIC_B64 = "rO0AB"  # base64 of \xac\xed\x00\x05

# PHP serialized object pattern
PHP_SERIAL_PATTERN = re.compile(r'[OCAsa]:\d+:', re.I)

# .NET ViewState pattern
VIEWSTATE_PATTERN = re.compile(r'__VIEWSTATE', re.I)
VIEWSTATE_ENCRYPTED = re.compile(r'__VIEWSTATEENCRYPTED', re.I)

# Gadget chain error signals (from known RCE exploit attempts)
JAVA_DESERIALIZATION_ERRORS = [
    re.compile(r"java\.io\.InvalidClassException", re.I),
    re.compile(r"java\.lang\.ClassNotFoundException", re.I),
    re.compile(r"ObjectInputStream", re.I),
    re.compile(r"readObject", re.I),
    re.compile(r"org\.apache\.commons\.collections", re.I),
    re.compile(r"com\.sun\.org\.apache\.xalan", re.I),
    re.compile(r"org\.springframework.*deseri", re.I),
]

PHP_DESERIALIZATION_ERRORS = [
    re.compile(r"unserialize\(\)", re.I),
    re.compile(r"__wakeup", re.I),
    re.compile(r"class '.+' not found", re.I),
    re.compile(r"failed to unserialize", re.I),
    re.compile(r"unserialization.+failed", re.I),
]


def _check_cookies_for_serialized_data(resp, url: str, findings: List[Finding]) -> None:
    """Detect if cookies contain serialized objects."""
    for cookie_name, cookie_value in resp.cookies.items():
        # Check for Java serialization
        if JAVA_SERIAL_MAGIC_B64 in cookie_value:
            findings.append(Finding(
                title=f"Java Serialized Object in Cookie: '{cookie_name}'",
                severity=Severity.CRITICAL,
                description=(
                    f"The cookie '{cookie_name}' contains a Java serialized object "
                    f"(magic bytes 0xACED detected). If the server deserializes this "
                    "without validation, attackers can craft malicious payloads using "
                    "known gadget chains (Apache Commons Collections, Spring, etc.) "
                    "to achieve Remote Code Execution."
                ),
                evidence=(
                    f"Cookie name: {cookie_name}\n"
                    f"Value start: {cookie_value[:50]}...\n"
                    f"Java serialization magic (rO0AB / 0xACED) detected"
                ),
                remediation=(
                    "Never deserialize untrusted data. "
                    "Use serialization alternatives: JSON with schema validation. "
                    "If Java deserialization is required, use a deserialization filter "
                    "(JEP 290) and sign serialized data with HMAC. "
                    "Use ysoserial gadget chain scanner to assess actual exploitability."
                ),
                code_fix=(
                    "# ❌ NEVER do this:\n"
                    "ObjectInputStream ois = new ObjectInputStream(inputStream);\n"
                    "Object obj = ois.readObject();  // VULNERABLE\n\n"
                    "# ✅ Use JSON instead:\n"
                    "import com.fasterxml.jackson.databind.ObjectMapper;\n"
                    "ObjectMapper mapper = new ObjectMapper();\n"
                    "MyClass obj = mapper.readValue(jsonString, MyClass.class);\n\n"
                    "# If you must deserialize — use a filter (Java 9+):\n"
                    "ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(\n"
                    "  'com.myapp.safe.*;!*');\n"
                    "ois.setObjectInputFilter(filter);"
                ),
                reference="https://owasp.org/www-project-top-ten/2017/A8_2017-Insecure_Deserialization",
                cvss=9.8,
            ))

        # Check for PHP serialized data
        try:
            decoded = base64.b64decode(cookie_value + "==")
            decoded_str = decoded.decode("utf-8", errors="ignore")
            if PHP_SERIAL_PATTERN.search(decoded_str):
                findings.append(Finding(
                    title=f"PHP Serialized Object in Cookie: '{cookie_name}'",
                    severity=Severity.HIGH,
                    description=(
                        f"The cookie '{cookie_name}' appears to contain a base64-encoded "
                        "PHP serialized object. If the server calls unserialize() on this "
                        "data, attackers can craft objects with __wakeup/__destruct methods "
                        "from known POP (Property Oriented Programming) chains to achieve RCE."
                    ),
                    evidence=(
                        f"Cookie: {cookie_name}\n"
                        f"Decoded (first 80 chars): {decoded_str[:80]}\n"
                        "PHP serialize() pattern detected"
                    ),
                    remediation=(
                        "Replace PHP unserialize() with json_decode(). "
                        "Never deserialize user-controlled data. "
                        "If unavoidable, sign the serialized data with HMAC "
                        "and verify before deserializing."
                    ),
                    code_fix=(
                        "# ❌ VULNERABLE:\n"
                        "$data = unserialize(base64_decode($_COOKIE['data']));\n\n"
                        "# ✅ SAFE — use JSON:\n"
                        "$data = json_decode(base64_decode($_COOKIE['data']), true);\n\n"
                        "# Or sign with HMAC:\n"
                        "$payload = base64_decode($_COOKIE['data']);\n"
                        "[$data, $sig] = explode('|', $payload, 2);\n"
                        "if (!hash_equals(hash_hmac('sha256', $data, SECRET), $sig)) {\n"
                        "    die('Tampered cookie');\n"
                        "}\n"
                        "$obj = unserialize($data);"
                    ),
                    reference="https://portswigger.net/web-security/deserialization",
                    cvss=8.1,
                ))
        except Exception:
            pass


def _check_viewstate(resp, url: str, findings: List[Finding]) -> None:
    """Check for unprotected .NET ViewState."""
    body = resp.text
    if not VIEWSTATE_PATTERN.search(body):
        return

    is_encrypted = bool(VIEWSTATE_ENCRYPTED.search(body))

    # Extract ViewState value
    vs_match = re.search(
        r'__VIEWSTATE[^>]*value=["\']([A-Za-z0-9+/=]{20,})["\']',
        body
    )
    if not vs_match:
        return

    vs_value = vs_match.group(1)

    # Try to decode it — if it decodes as base64 and starts with common patterns
    try:
        decoded = base64.b64decode(vs_value)
        if decoded[:2] == b'\xff\x01' or decoded[:4] == b'\x0f\xb0\x12\xed':
            encrypted = False
        else:
            encrypted = True
    except Exception:
        encrypted = is_encrypted

    if not encrypted:
        findings.append(Finding(
            title=".NET ViewState Not Encrypted / Not Validated with MAC",
            severity=Severity.HIGH,
            description=(
                "The .NET ViewState is present but does not appear to be encrypted or "
                "protected with a Message Authentication Code (MAC). "
                "Attackers can craft malicious ViewState payloads that execute arbitrary "
                ".NET code when deserialized by the server (if using ObjectStateFormatter). "
                "This is exploitable with ysoserial.net."
            ),
            evidence=(
                f"__VIEWSTATE found in response\n"
                f"Encrypted: {encrypted}\n"
                f"ViewState sample: {vs_value[:60]}..."
            ),
            remediation=(
                "Enable ViewState MAC validation in web.config. "
                "Enable ViewState encryption for sensitive pages. "
                "Consider switching to token-based authentication instead."
            ),
            code_fix=(
                "<!-- web.config — enable ViewState MAC and encryption: -->\n"
                "<system.web>\n"
                "  <pages enableViewStateMac='true' viewStateEncryptionMode='Always' />\n"
                "  <machineKey validationKey='AUTO' decryptionKey='AUTO'\n"
                "    validation='HMACSHA256' decryption='AES' />\n"
                "</system.web>"
            ),
            reference="https://portswigger.net/web-security/deserialization/exploiting",
            cvss=8.1,
        ))


def _check_deserialization_errors(client, url: str, findings: List[Finding]) -> None:
    """
    Send malformed serialized payloads and look for error messages
    that reveal deserialization internals.
    """
    from urllib.parse import parse_qs, urlunparse, urlencode

    parsed = urlparse(url)
    params = list(parse_qs(parsed.query, keep_blank_values=True).keys())

    # Malformed Java serialized object (triggers error if deserializing)
    java_garbage = base64.b64encode(b'\xac\xed\x00\x05' + b'\x00' * 20).decode()
    # Malformed PHP serialized string
    php_garbage = base64.b64encode(b'O:99:"EvilClass":1:{s:4:"data";s:5:"value";}').decode()

    test_payloads = [java_garbage, php_garbage, "rO0ABXN=", "Tzo4OiJ"]

    for param in params[:3]:
        for payload in test_payloads:
            qs = dict(parse_qs(parsed.query, keep_blank_values=True))
            qs[param] = payload
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path, parsed.params,
                urlencode(qs), ""
            ))
            try:
                resp = client.get(test_url)
                for pattern in JAVA_DESERIALIZATION_ERRORS + PHP_DESERIALIZATION_ERRORS:
                    if pattern.search(resp.text):
                        findings.append(Finding(
                            title=f"Deserialization Error Exposed | param: {param}",
                            severity=Severity.HIGH,
                            description=(
                                f"A deserialization-related error was triggered by sending "
                                f"a malformed serialized payload to '{param}'. "
                                "This confirms the server deserializes user-supplied data, "
                                "and the error message reveals implementation details. "
                                "Attackers can craft exploit gadget chains to achieve RCE."
                            ),
                            evidence=(
                                f"Parameter: {param}\n"
                                f"Pattern matched: {pattern.pattern}\n"
                                f"Response: {resp.text[:300]}"
                            ),
                            remediation=(
                                "Never deserialize user-controlled data. "
                                "Switch to JSON/protobuf with schema validation. "
                                "If deserialization is required, use allowlist filtering "
                                "and sign all serialized data with HMAC."
                            ),
                            reference="https://portswigger.net/web-security/deserialization",
                            cvss=8.8,
                        ))
                        return
            except Exception:
                continue


def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    from urllib.parse import urlparse as _up
    parsed = _up(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    # Probe paths that commonly set session/serialization cookies
    probe_paths = ["", "/app", "/profile", "/account", "/session", "/login"]

    with get_client(timeout=min(timeout, 8.0)) as client:
        for path in probe_paths:
            try:
                resp = client.get(base + path)
                if resp.status_code not in (200, 302):
                    continue
                _check_cookies_for_serialized_data(resp, base + path, findings)
                _check_viewstate(resp, base + path, findings)
                if findings:
                    return findings
            except Exception:
                continue

        # Check deserialization errors in URL params
        try:
            resp = client.get(url)
            if not findings:
                _check_deserialization_errors(client, url, findings)
        except Exception:
            pass

    return findings
