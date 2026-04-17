"""Tests for v1.2.0 new modules."""
import pytest
from unittest.mock import patch, MagicMock
import httpx

from webshield.core.models import Severity
from webshield.modules import (
    sql_injection, xss_detection, lfi, xxe,
    csrf_check, malware_indicators, broken_links, log4shell
)


def _mock(headers=None, status=200, body="<html></html>", url="https://example.com"):
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status
    resp.headers = httpx.Headers(headers or {"content-type": "text/html"})
    resp.text = body
    resp.content = body.encode()
    resp.cookies = httpx.Cookies()
    return resp


# ── SQL Injection ────────────────────────────────────────────────────

def test_sqli_mysql_error():
    error_body = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"
    mock_base = _mock(body="normal page")
    mock_error = _mock(body=error_body)
    responses = [mock_base] + [mock_error] * 20
    with patch("webshield.modules.sql_injection.get_client") as mc:
        mc.return_value.__enter__.return_value.get.side_effect = responses
        findings = sql_injection.scan("https://example.com?id=1")
    assert any("SQL Injection" in f.title for f in findings)
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_sqli_postgres_error():
    error_body = "PG::SyntaxError: ERROR:  syntax error at or near end of input"
    mock_base = _mock(body="normal page")
    mock_error = _mock(body=error_body)
    with patch("webshield.modules.sql_injection.get_client") as mc:
        mc.return_value.__enter__.return_value.get.side_effect = [mock_base] + [mock_error] * 20
        findings = sql_injection.scan("https://example.com?id=1")
    assert any("PostgreSQL" in f.title for f in findings)


def test_sqli_no_params():
    with patch("webshield.modules.sql_injection.get_client") as mc:
        findings = sql_injection.scan("https://example.com")
    assert len(findings) == 0


def test_sqli_clean():
    mock = _mock(body="<html>normal response</html>")
    with patch("webshield.modules.sql_injection.get_client") as mc:
        mc.return_value.__enter__.return_value.get.return_value = mock
        findings = sql_injection.scan("https://example.com?id=1")
    assert not any("SQL Injection" in f.title for f in findings)


# ── XSS Detection ────────────────────────────────────────────────────

def test_xss_reflected():
    canary = "wshld9x7z"
    body = f'<html><p>Search: <script>{canary}</script></p></html>'
    mock_base = _mock(body="<html>normal</html>")
    mock_xss = _mock(body=body)
    with patch("webshield.modules.xss_detection.get_client") as mc:
        mc.return_value.__enter__.return_value.get.side_effect = [mock_base] + [mock_xss] * 20
        findings = xss_detection.scan("https://example.com?q=test")
    assert any("XSS" in f.title and "Reflected" in f.title for f in findings)
    assert any(f.severity == Severity.HIGH for f in findings)


def test_xss_encoded_safe():
    canary = "wshld9x7z"
    body = f'<html><p>Search: &lt;{canary}&gt;</p></html>'
    mock_base = _mock(body="<html>normal</html>")
    mock_enc = _mock(body=body)
    with patch("webshield.modules.xss_detection.get_client") as mc:
        mc.return_value.__enter__.return_value.get.side_effect = [mock_base] + [mock_enc] * 20
        findings = xss_detection.scan("https://example.com?q=test")
    # Encoded = LOW severity (not HIGH)
    high = [f for f in findings if f.severity == Severity.HIGH and "Reflected" in f.title]
    assert len(high) == 0


def test_xss_no_params():
    findings = xss_detection.scan("https://example.com")
    assert len(findings) == 0


# ── LFI ─────────────────────────────────────────────────────────────

def test_lfi_passwd():
    passwd_content = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
    mock_base = _mock(body="<html>normal</html>")
    mock_lfi = _mock(body=passwd_content)
    with patch("webshield.modules.lfi.get_client") as mc:
        mc.return_value.__enter__.return_value.get.side_effect = [mock_base] + [mock_lfi] * 20
        findings = lfi.scan("https://example.com?file=index.php")
    assert any("LFI" in f.title for f in findings)
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_lfi_no_params():
    findings = lfi.scan("https://example.com")
    assert len(findings) == 0


# ── XXE ─────────────────────────────────────────────────────────────

def test_xxe_passwd():
    passwd = "root:x:0:0:root:/root:/bin/bash"
    mock_probe = _mock(status=200, body="<root>test</root>")
    mock_xxe = _mock(status=200, body=f"<root>{passwd}</root>")
    with patch("webshield.modules.xxe.get_client") as mc:
        mc.return_value.__enter__.return_value.post.side_effect = [mock_probe] + [mock_xxe] * 10
        findings = xxe.scan("https://example.com/api")
    assert any("XXE" in f.title for f in findings)
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_xxe_rejected():
    mock = _mock(status=415, body="Unsupported Media Type")
    with patch("webshield.modules.xxe.get_client") as mc:
        mc.return_value.__enter__.return_value.post.return_value = mock
        findings = xxe.scan("https://example.com/api")
    assert len(findings) == 0


# ── CSRF ─────────────────────────────────────────────────────────────

def test_csrf_form_missing_token():
    body = """
    <html><form method="POST" action="/login">
        <input type="text" name="username">
        <input type="password" name="password">
        <input type="submit" value="Login">
    </form></html>
    """
    mock = _mock(body=body, headers={"content-type": "text/html"})
    with patch("webshield.modules.csrf_check.get_client") as mc:
        mc.return_value.__enter__.return_value.get.return_value = mock
        findings = csrf_check.scan("https://example.com")
    assert any("CSRF" in f.title for f in findings)


def test_csrf_form_with_token():
    body = """
    <html><form method="POST" action="/submit">
        <input type="hidden" name="_token" value="abc123def456ghi789jkl012mno345pq">
        <input type="text" name="data">
        <input type="submit">
    </form></html>
    """
    mock = _mock(body=body, headers={"content-type": "text/html"})
    with patch("webshield.modules.csrf_check.get_client") as mc:
        mc.return_value.__enter__.return_value.get.return_value = mock
        findings = csrf_check.scan("https://example.com")
    # Token is present — no "CSRF Protection Missing" finding expected
    csrf_missing = [f for f in findings if "CSRF Protection Missing" in f.title]
    assert len(csrf_missing) == 0


# ── Malware Indicators ───────────────────────────────────────────────

def test_malware_cryptominer():
    body = "<html><script src='https://coinhive.com/lib/coinhive.min.js'></script></html>"
    mock = _mock(body=body)
    with patch("webshield.modules.malware_indicators.get_client") as mc:
        mc.return_value.__enter__.return_value.get.return_value = mock
        findings = malware_indicators.scan("https://example.com")
    assert any("Miner" in f.title or "miner" in f.title.lower() for f in findings)
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_malware_webshell():
    body = "<html><?php eval(base64_decode($_GET['cmd'])); ?></html>"
    mock = _mock(body=body)
    with patch("webshield.modules.malware_indicators.get_client") as mc:
        mc.return_value.__enter__.return_value.get.return_value = mock
        findings = malware_indicators.scan("https://example.com")
    assert any("Web Shell" in f.title or "Shell" in f.title for f in findings)


def test_malware_seo_spam():
    body = "<html><p>buy cheap viagra online pharmacy discount</p></html>"
    mock = _mock(body=body)
    with patch("webshield.modules.malware_indicators.get_client") as mc:
        mc.return_value.__enter__.return_value.get.return_value = mock
        findings = malware_indicators.scan("https://example.com")
    assert any("Spam" in f.title for f in findings)


def test_malware_clean_page():
    mock = _mock(body="<html><body><h1>Welcome to Example</h1></body></html>")
    with patch("webshield.modules.malware_indicators.get_client") as mc:
        mc.return_value.__enter__.return_value.get.return_value = mock
        findings = malware_indicators.scan("https://example.com")
    assert len(findings) == 0


# ── Module count check ───────────────────────────────────────────────

def test_v120_module_count():
    from webshield.core.scanner import ALL_MODULES
    assert len(ALL_MODULES) >= 35  # 39 as of v1.3.0
    for mod in ["sql_injection", "xss_detection", "lfi", "xxe",
                "log4shell", "csrf_check", "malware_indicators", "broken_links"]:
        assert mod in ALL_MODULES, f"Missing: {mod}"


def test_v120_all_importable():
    import importlib
    from webshield.core.scanner import ALL_MODULES
    failed = []
    for mod in ALL_MODULES:
        try:
            importlib.import_module(f"webshield.modules.{mod}")
        except Exception as e:
            failed.append(f"{mod}: {e}")
    assert failed == [], f"Import failures: {failed}"
