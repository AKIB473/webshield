"""
SQL Injection Detection Module (v1.2.0)
Error-based SQLi — detects across MySQL, PostgreSQL, MSSQL, Oracle, SQLite.
Learned from: Wapiti mod_sql.py (best DBMS error patterns anywhere), Greaper, w4af
"""

from __future__ import annotations
import re
from typing import List, Dict
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

SQLI_PROBES = [
    "'", "''", "\"", "\\", "1'", "1\"",
    "' OR '1'='1", "' OR 1=1--",
    "1 AND 1=2", "' AND '1'='2",
]

DBMS_ERRORS: Dict[str, List[re.Pattern]] = {
    "MySQL": [
        re.compile(r"SQL syntax.*?MySQL", re.I),
        re.compile(r"Warning.*?\Wmysqli?_", re.I),
        re.compile(r"MySQLSyntaxErrorException", re.I),
        re.compile(r"check the manual that (corresponds to|fits) your MySQL server version", re.I),
        re.compile(r"Unknown column '[^ ]+' in 'field list'", re.I),
        re.compile(r"MySqlException", re.I),
        re.compile(r"SQLSTATE\[\d+\]: Syntax error", re.I),
    ],
    "PostgreSQL": [
        re.compile(r"PostgreSQL.*?ERROR", re.I),
        re.compile(r"Warning.*?\Wpg_", re.I),
        re.compile(r"PG::SyntaxError:", re.I),
        re.compile(r"org\.postgresql\.util\.PSQLException", re.I),
        re.compile(r"ERROR:\s\ssyntax error at or near", re.I),
        re.compile(r"PostgreSQL query failed", re.I),
    ],
    "Microsoft SQL Server": [
        re.compile(r"Driver.*? SQL[\-\_\ ]*Server", re.I),
        re.compile(r"Warning.*?\W(mssql|sqlsrv)_", re.I),
        re.compile(r"System\.Data\.SqlClient\.SqlException", re.I),
        re.compile(r"Microsoft SQL Native Client error", re.I),
        re.compile(r"ODBC SQL Server Driver", re.I),
        re.compile(r"SQL(Srv|Server)Exception", re.I),
    ],
    "Oracle": [
        re.compile(r"\bORA-[0-9]{4,}", re.I),
        re.compile(r"Oracle error", re.I),
        re.compile(r"Warning.*?\Woci_", re.I),
        re.compile(r"quoted string not properly terminated", re.I),
        re.compile(r"OracleException", re.I),
    ],
    "SQLite": [
        re.compile(r"SQLite\.Exception", re.I),
        re.compile(r"Warning.*?\Wsqlite_", re.I),
        re.compile(r"sqlite3\.OperationalError:", re.I),
        re.compile(r"\[SQLITE_ERROR\]", re.I),
    ],
    "Generic": [
        re.compile(r"SQL command not properly ended", re.I),
        re.compile(r"unexpected end of SQL command", re.I),
        re.compile(r"Unclosed quotation mark.*SQL", re.I),
        re.compile(r"invalid SQL statement", re.I),
        re.compile(r"You have an error in your SQL syntax", re.I),
    ],
}

ALL_PATTERNS = [(dbms, pat) for dbms, pats in DBMS_ERRORS.items() for pat in pats]


def scan(url: str, timeout: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    parsed = urlparse(url)
    params = list(parse_qs(parsed.query, keep_blank_values=True).keys())

    if not params:
        return []

    with get_client(timeout=min(timeout, 8.0)) as client:
        try:
            baseline = client.get(url).text
        except Exception:
            return []

        for param in params[:5]:
            for probe in SQLI_PROBES[:8]:
                # Build test URL
                all_params = parse_qs(parsed.query, keep_blank_values=True)
                new_params = {k: v[0] if isinstance(v, list) else v for k, v in all_params.items()}
                new_params[param] = probe
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, urlencode(new_params), ""
                ))
                try:
                    body = client.get(test_url).text
                except Exception:
                    continue

                if not body or body == baseline:
                    continue

                for (dbms, pattern) in ALL_PATTERNS:
                    if pattern.search(body):
                        findings.append(Finding(
                            title=f"SQL Injection — {dbms} Error Detected (param: {param})",
                            severity=Severity.CRITICAL,
                            description=(
                                f"A {dbms} database error was triggered by injecting "
                                f"'{probe}' into the '{param}' parameter. This is a strong "
                                "indicator of SQL injection vulnerability. Attackers can use "
                                "this to read, modify, or delete all database content, "
                                "bypass authentication, and potentially execute OS commands."
                            ),
                            evidence=(
                                f"Parameter: {param}\n"
                                f"Payload: {probe!r}\n"
                                f"DBMS: {dbms}\n"
                                f"Error pattern matched: {pattern.pattern[:80]}\n"
                                f"Response snippet: {body[:300]}"
                            ),
                            remediation=(
                                "Use parameterized queries / prepared statements. "
                                "NEVER concatenate user input into SQL strings."
                            ),
                            code_fix=(
                                "# WRONG — vulnerable:\n"
                                f"query = f\"SELECT * FROM users WHERE id = '{{user_input}}'\"\n\n"
                                "# CORRECT — parameterized:\n"
                                "cursor.execute('SELECT * FROM users WHERE id = %s', (user_input,))\n\n"
                                "# Python SQLAlchemy ORM (also safe):\n"
                                "User.query.filter_by(id=user_input).first()\n\n"
                                "# Node.js:\n"
                                "db.query('SELECT * FROM users WHERE id = ?', [userId])"
                            ),
                            reference="https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                            cvss=9.8,
                        ))
                        return findings  # one per site is enough

    return findings
