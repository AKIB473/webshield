"""Suspicious Comments & Debug Info Module (v1.8.0) — ZAP rule 10027"""
from __future__ import annotations
import re
from typing import List
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

COMMENT_PATTERNS = [
    (re.compile(r'<!--.*?(password|passwd|pwd|secret|api.?key|token|credential|auth|private).*?-->', re.I|re.S),
     "Credential/Secret in HTML Comment", Severity.HIGH, 7.5),
    (re.compile(r'<!--.*?(TODO|FIXME|HACK|XXX|BUG|VULNERABILITY|INSECURE|REMOVE|TEMP|DISABLE).*?-->', re.I|re.S),
     "Development Comment Left in Production", Severity.LOW, 3.1),
    (re.compile(r'<!--.*?(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE TABLE|WHERE|FROM).*?-->', re.I|re.S),
     "SQL Fragment in HTML Comment", Severity.MEDIUM, 5.3),
    (re.compile(r'<!--.*?(192\.168\.|10\.\d+\.|172\.(1[6-9]|2[0-9]|3[01])\.).*?-->', re.I),
     "Internal IP Address in HTML Comment", Severity.MEDIUM, 4.3),
    (re.compile(r'//\s*(password|secret|api.?key|token)\s*[=:]\s*["\']?[\w\-]+', re.I),
     "Credential in JS Comment", Severity.HIGH, 7.5),
    (re.compile(r'//\s*(TODO|FIXME|HACK|XXX|VULNERABILITY|INSECURE)', re.I),
     "Development Note in JS Comment", Severity.LOW, 2.0),
]

DEBUG_PATTERNS = [
    (re.compile(r'<b>(?:Notice|Warning|Fatal error|Parse error):</b>.*?(?:in|on line)', re.I|re.S),
     "PHP Error Message Disclosed", Severity.MEDIUM, 5.3),
    (re.compile(r'Traceback \(most recent call last\)', re.I),
     "Python Traceback Disclosed", Severity.MEDIUM, 5.3),
    (re.compile(r'at\s+[\w\.]+\([\w\.]+\.java:\d+\)', re.I),
     "Java Stack Trace Disclosed", Severity.MEDIUM, 5.3),
    (re.compile(r'System\.Web\.HttpException|ASP\.NET.*Exception', re.I),
     "ASP.NET Exception Disclosed", Severity.MEDIUM, 5.3),
    (re.compile(r'DEBUG\s*=\s*True|development\s*mode|debug\s*mode\s*enabled', re.I),
     "Debug Mode Enabled", Severity.HIGH, 7.5),
]

def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    with get_client(timeout=min(timeout, 8.0)) as client:
        try:
            resp = client.get(url)
            if resp.status_code != 200:
                return findings
            body = resp.text[:100000]

            for (pattern, title, severity, cvss) in COMMENT_PATTERNS:
                m = pattern.search(body)
                if m:
                    snippet = m.group(0)[:150].strip()
                    findings.append(Finding(
                        title=title,
                        severity=severity,
                        description=(
                            f"Found in HTML/JS source: {title}. "
                            "Debug comments and development notes in production source code "
                            "can reveal passwords, internal IPs, SQL queries, and business logic."
                        ),
                        evidence=f"URL: {url}\nMatch: {snippet}",
                        remediation="Remove all debug comments before deploying to production. Use a build process that strips comments.",
                        code_fix=(
                            "# Webpack — remove comments in production:\n"
                            "optimization: { minimize: true,\n"
                            "  minimizer: [new TerserPlugin({ terserOptions: { format: { comments: false } } })] }"
                        ),
                        reference="https://owasp.org/www-project-web-security-testing-guide/",
                        module="suspicious_comments",
                        cvss=cvss,
                    ))

            for (pattern, title, severity, cvss) in DEBUG_PATTERNS:
                m = pattern.search(body)
                if m:
                    findings.append(Finding(
                        title=title,
                        severity=severity,
                        description=f"{title} reveals internal application structure and file paths to attackers.",
                        evidence=f"URL: {url}\nMatch: {m.group(0)[:150]}",
                        remediation="Disable debug mode in production. Use error pages that don't expose stack traces.",
                        code_fix=(
                            "# Django: DEBUG = False\n"
                            "# Laravel: APP_DEBUG=false in .env\n"
                            "# Express: app.use(errorHandler) only in dev"
                        ),
                        reference="https://owasp.org/www-project-web-security-testing-guide/",
                        module="suspicious_comments",
                        cvss=cvss,
                    ))
        except Exception:
            pass
    return findings
