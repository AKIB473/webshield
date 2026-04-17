"""
SQL Injection Detection Module (v1.3.0 — Advanced)
Covers: Error-based, Boolean-blind, Time-based blind, Union-based, WAF bypass.
Multi-DBMS: MySQL, PostgreSQL, MSSQL, Oracle, SQLite.
Techniques from: sqlmap, Wapiti, PortSwigger research, SQLi WAF bypass research 2024/2025.
"""

from __future__ import annotations
import re
import time
from typing import List, Dict, Tuple, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

# ─── DBMS Error Patterns ──────────────────────────────────────────────────────

DBMS_ERRORS: Dict[str, List[re.Pattern]] = {
    "MySQL": [
        re.compile(r"SQL syntax.*?MySQL", re.I),
        re.compile(r"Warning.*?\Wmysqli?_", re.I),
        re.compile(r"MySQLSyntaxErrorException", re.I),
        re.compile(r"check the manual that (corresponds to|fits) your MySQL server version", re.I),
        re.compile(r"Unknown column '[^ ]+' in 'field list'", re.I),
        re.compile(r"MySqlException", re.I),
        re.compile(r"SQLSTATE\[\d+\]: Syntax error", re.I),
        re.compile(r"mysql_fetch_array\(\)", re.I),
        re.compile(r"Duplicate entry .+ for key", re.I),
    ],
    "PostgreSQL": [
        re.compile(r"PostgreSQL.*?ERROR", re.I),
        re.compile(r"Warning.*?\Wpg_", re.I),
        re.compile(r"PG::SyntaxError:", re.I),
        re.compile(r"org\.postgresql\.util\.PSQLException", re.I),
        re.compile(r"ERROR:\s+syntax error at or near", re.I),
        re.compile(r"unterminated quoted string at or near", re.I),
        re.compile(r"invalid input syntax for (type |integer)", re.I),
    ],
    "Microsoft SQL Server": [
        re.compile(r"Driver.*? SQL[\-\_\ ]*Server", re.I),
        re.compile(r"Warning.*?\W(mssql|sqlsrv)_", re.I),
        re.compile(r"System\.Data\.SqlClient\.SqlException", re.I),
        re.compile(r"Microsoft SQL Native Client error", re.I),
        re.compile(r"ODBC SQL Server Driver", re.I),
        re.compile(r"SQL(Srv|Server)Exception", re.I),
        re.compile(r"Unclosed quotation mark after the character string", re.I),
        re.compile(r"Incorrect syntax near", re.I),
    ],
    "Oracle": [
        re.compile(r"\bORA-[0-9]{4,}", re.I),
        re.compile(r"Oracle error", re.I),
        re.compile(r"Warning.*?\Woci_", re.I),
        re.compile(r"quoted string not properly terminated", re.I),
        re.compile(r"OracleException", re.I),
        re.compile(r"oracle\.jdbc\.driver", re.I),
    ],
    "SQLite": [
        re.compile(r"SQLite\.Exception", re.I),
        re.compile(r"Warning.*?\Wsqlite_", re.I),
        re.compile(r"sqlite3\.OperationalError:", re.I),
        re.compile(r"\[SQLITE_ERROR\]", re.I),
        re.compile(r"unrecognized token:", re.I),
    ],
    "Generic": [
        re.compile(r"SQL command not properly ended", re.I),
        re.compile(r"unexpected end of SQL command", re.I),
        re.compile(r"Unclosed quotation mark.*SQL", re.I),
        re.compile(r"You have an error in your SQL syntax", re.I),
        re.compile(r"supplied argument is not a valid MySQL", re.I),
        re.compile(r"Column count doesn't match value count", re.I),
    ],
}

ALL_ERROR_PATTERNS = [(dbms, pat) for dbms, pats in DBMS_ERRORS.items() for pat in pats]

# ─── Error-Based Payloads ─────────────────────────────────────────────────────

ERROR_PROBES = [
    "'", '"', "''",
    "'--", "'#", "' --",
    "1' AND '1'='2",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    # WAF bypass — comment injection + case variation
    "'/**/OR/**/1=1--",
    "'||'1'='1",
    "1'%09AND%09'1'='2",       # tab-encoded
    "1' AND 0x31=0x32--",      # hex comparison
    "' OR 'x'='x",
    "\\'", "\\\"",
]

# ─── Boolean-Blind Probe Pairs ────────────────────────────────────────────────

BOOLEAN_PAIRS: List[Tuple[str, str]] = [
    ("1' AND '1'='1'--", "1' AND '1'='2'--"),
    ("1 AND 1=1", "1 AND 1=2"),
    ("1' AND 1=1--", "1' AND 1=2--"),
    ("' OR 1=1--", "' OR 1=2--"),
    ("1'/**/AND/**/'1'='1", "1'/**/AND/**/'1'='2"),
    ("1' AND 0x31=0x31--", "1' AND 0x31=0x32--"),
    # PostgreSQL
    ("1' AND TRUE--", "1' AND FALSE--"),
]

# ─── Time-Based Blind Probes ──────────────────────────────────────────────────

TIME_PROBES: List[Tuple[str, float, str]] = [
    ("' AND SLEEP(4)--",                    4.0, "MySQL"),
    ("' OR SLEEP(4)--",                     4.0, "MySQL"),
    ("1' AND (SELECT 1 FROM (SELECT SLEEP(4))x)--", 4.0, "MySQL"),
    ("'/**/AND/**/SLEEP(4)--",              4.0, "MySQL (WAF bypass)"),
    ("1 AND SLEEP(4)--",                    4.0, "MySQL"),
    ("'; SELECT pg_sleep(4)--",             4.0, "PostgreSQL"),
    ("' AND 1=(SELECT 1 FROM pg_sleep(4))--", 4.0, "PostgreSQL"),
    ("'; WAITFOR DELAY '0:0:4'--",          4.0, "MSSQL"),
    ("' IF(1=1) WAITFOR DELAY '0:0:4'--",  4.0, "MSSQL"),
    ("' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',4)--", 4.0, "Oracle"),
]

SLEEP_THRESHOLD = 3.0


def _build_url(url: str, param: str, value: str) -> str:
    p = urlparse(url)
    params = {k: v[0] if isinstance(v, list) else v
              for k, v in parse_qs(p.query, keep_blank_values=True).items()}
    params[param] = value
    return urlunparse((p.scheme, p.netloc, p.path, p.params, urlencode(params), ""))


def _error_scan(client, url: str, params: List[str], baseline: str) -> Optional[Finding]:
    for param in params[:6]:
        for probe in ERROR_PROBES:
            try:
                body = client.get(_build_url(url, param, probe)).text
            except Exception:
                continue
            if not body or body.strip() == baseline.strip():
                continue
            for dbms, pattern in ALL_ERROR_PATTERNS:
                if pattern.search(body):
                    return Finding(
                        title=f"SQL Injection (Error-Based) — {dbms} | param: {param}",
                        severity=Severity.CRITICAL,
                        description=(
                            f"A {dbms} database error was triggered by injecting '{probe}' "
                            f"into '{param}'. Error-based SQLi allows attackers to read the "
                            "entire database, extract credentials, bypass authentication, "
                            "and potentially execute OS commands."
                        ),
                        evidence=(
                            f"Parameter: {param}\nPayload: {probe!r}\nDBMS: {dbms}\n"
                            f"Pattern: {pattern.pattern[:80]}\n"
                            f"Response snippet: {body[:400]}"
                        ),
                        remediation="Use parameterized queries. Never concatenate user input into SQL.",
                        code_fix=(
                            "# ❌ VULNERABLE:\n"
                            "query = f\"SELECT * FROM users WHERE id = '{user_input}'\"\n\n"
                            "# ✅ Parameterized (Python):\n"
                            "cursor.execute('SELECT * FROM users WHERE id = %s', (user_input,))\n\n"
                            "# ✅ SQLAlchemy ORM:\n"
                            "User.query.filter(User.id == user_input).first()\n\n"
                            "# ✅ Node.js (pg):\n"
                            "client.query('SELECT * FROM users WHERE id = $1', [userId])\n\n"
                            "# ✅ Java PreparedStatement:\n"
                            "PreparedStatement ps = conn.prepareStatement(\n"
                            "    'SELECT * FROM users WHERE id = ?');\n"
                            "ps.setString(1, userId);"
                        ),
                        reference="https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                        cvss=9.8,
                    )
    return None


def _boolean_scan(client, url: str, params: List[str]) -> Optional[Finding]:
    """Detects blind boolean-based SQLi by comparing true vs false condition responses."""
    for param in params[:4]:
        for (true_payload, false_payload) in BOOLEAN_PAIRS:
            try:
                r_true  = client.get(_build_url(url, param, true_payload)).text
                r_false = client.get(_build_url(url, param, false_payload)).text
            except Exception:
                continue

            if not r_true or not r_false:
                continue

            # Responses must differ meaningfully — same length ±5% = likely same
            len_true, len_false = len(r_true), len(r_false)
            if len_true == 0 or len_false == 0:
                continue

            diff_ratio = abs(len_true - len_false) / max(len_true, len_false)
            content_differs = r_true.strip() != r_false.strip()

            if diff_ratio > 0.05 and content_differs:
                return Finding(
                    title=f"SQL Injection (Boolean-Blind) Detected | param: {param}",
                    severity=Severity.CRITICAL,
                    description=(
                        f"Boolean-based blind SQL injection detected on parameter '{param}'. "
                        "The server returns different responses for TRUE vs FALSE SQL conditions, "
                        "confirming the injected logic is being evaluated. Attackers can extract "
                        "the full database contents bit-by-bit without any visible errors."
                    ),
                    evidence=(
                        f"Parameter: {param}\n"
                        f"TRUE payload: {true_payload!r} → {len_true} bytes\n"
                        f"FALSE payload: {false_payload!r} → {len_false} bytes\n"
                        f"Response length difference: {abs(len_true - len_false)} bytes ({diff_ratio:.0%})"
                    ),
                    remediation="Use parameterized queries. Input validation alone is insufficient.",
                    code_fix=(
                        "# All database queries MUST use parameterized inputs.\n"
                        "# See error-based SQLi fix above — same solution applies."
                    ),
                    reference="https://portswigger.net/web-security/sql-injection/blind",
                    cvss=9.8,
                )
    return None


def _time_scan(client, url: str, params: List[str], base_time: float) -> Optional[Finding]:
    """Detects time-based blind SQLi via response delay measurement."""
    for param in params[:3]:
        for (payload, delay, dbms) in TIME_PROBES[:6]:
            test_url = _build_url(url, param, payload)
            try:
                t0 = time.monotonic()
                client.get(test_url, timeout=delay + 2.0)  # cap per-probe timeout
                elapsed = time.monotonic() - t0
            except Exception:
                continue

            if elapsed >= (delay - 0.5) and elapsed >= (base_time + SLEEP_THRESHOLD):
                return Finding(
                    title=f"SQL Injection (Time-Based Blind) — {dbms} | param: {param}",
                    severity=Severity.CRITICAL,
                    description=(
                        f"Time-based blind SQL injection confirmed on '{param}'. "
                        f"The payload '{payload}' caused a {elapsed:.1f}s response delay "
                        f"(baseline: {base_time:.1f}s), confirming {dbms} SQL execution. "
                        "Attackers can extract the full database without any visible output."
                    ),
                    evidence=(
                        f"Parameter: {param}\n"
                        f"Payload: {payload!r}\n"
                        f"DBMS detected: {dbms}\n"
                        f"Response time: {elapsed:.2f}s (baseline: {base_time:.2f}s)\n"
                        f"Delay triggered: {elapsed - base_time:.2f}s above baseline"
                    ),
                    remediation="Use parameterized queries. Never pass user input directly to SQL.",
                    code_fix=(
                        "# Parameterized queries prevent ALL SQLi types including time-based.\n"
                        "cursor.execute('SELECT * FROM users WHERE id = %s', (user_input,))"
                    ),
                    reference="https://portswigger.net/web-security/sql-injection/blind#exploiting-blind-sql-injection-by-triggering-time-delays",
                    cvss=9.8,
                )
    return None


def _union_scan(client, url: str, params: List[str], baseline: str) -> Optional[Finding]:
    """Detect UNION-based SQLi by probing column counts 1-10."""
    union_payloads = [
        f"' UNION SELECT {','.join(['NULL'] * i)}--"
        for i in range(1, 8)
    ] + [
        f"' UNION SELECT {','.join(['NULL'] * i)}#"
        for i in range(1, 5)
    ]

    for param in params[:3]:
        for payload in union_payloads:
            try:
                body = client.get(_build_url(url, param, payload)).text
            except Exception:
                continue
            if not body:
                continue
            # A successful UNION injection often returns more data or different length
            if len(body) > len(baseline) * 1.15:
                # Check for null markers or extra rows
                for dbms, pattern in ALL_ERROR_PATTERNS:
                    if pattern.search(body):
                        break  # This triggered an error, not a success
                else:
                    return Finding(
                        title=f"SQL Injection (UNION-Based) Possible | param: {param}",
                        severity=Severity.HIGH,
                        description=(
                            f"A UNION SELECT payload on '{param}' returned a significantly "
                            "larger response than baseline, suggesting successful column-count "
                            "discovery for UNION-based SQL injection."
                        ),
                        evidence=(
                            f"Parameter: {param}\nPayload: {payload!r}\n"
                            f"Baseline size: {len(baseline)} bytes\n"
                            f"Injected response: {len(body)} bytes"
                        ),
                        remediation="Use parameterized queries. Never concatenate user input into SQL.",
                        reference="https://portswigger.net/web-security/sql-injection/union-attacks",
                        cvss=9.1,
                    )
    return None


def scan(url: str, timeout: float = 12.0) -> List[Finding]:
    findings: List[Finding] = []
    parsed = urlparse(url)
    params = list(parse_qs(parsed.query, keep_blank_values=True).keys())

    if not params:
        return []

    with get_client(timeout=min(timeout, 10.0)) as client:
        try:
            t0 = time.monotonic()
            baseline_resp = client.get(url)
            base_time = time.monotonic() - t0
            baseline = baseline_resp.text
        except Exception:
            return []

        # 1. Error-based (fastest, most reliable)
        result = _error_scan(client, url, params, baseline)
        if result:
            findings.append(result)
            return findings  # error-based confirms it — no need to continue

        # 2. Boolean-blind
        result = _boolean_scan(client, url, params)
        if result:
            findings.append(result)
            return findings

        # 3. UNION-based
        result = _union_scan(client, url, params, baseline)
        if result:
            findings.append(result)
            return findings

        # 4. Time-based blind (slowest — only if others found nothing)
        result = _time_scan(client, url, params, base_time)
        if result:
            findings.append(result)

    return findings
