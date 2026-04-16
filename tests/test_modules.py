"""Tests for individual scan modules using a mock HTTP server."""
import pytest
from unittest.mock import patch, MagicMock
import httpx

from webshield.core.models import Severity
from webshield.modules import headers, cookies, cors, csp


# ── Headers module ────────────────────────────────────────────────────

def _mock_response(headers_dict: dict, status: int = 200, body: str = "<html></html>"):
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status
    resp.headers = httpx.Headers(headers_dict)
    resp.text = body
    resp.content = body.encode()
    resp.cookies = httpx.Cookies()
    return resp


def test_headers_all_missing():
    mock_resp = _mock_response({"content-type": "text/html"})
    with patch("webshield.modules.headers.get_client") as mock_client:
        mock_client.return_value.__enter__.return_value.get.return_value = mock_resp
        findings = headers.scan("https://example.com")
    titles = [f.title for f in findings]
    assert any("Strict-Transport-Security" in t for t in titles)
    assert any("Content-Security-Policy" in t for t in titles)
    assert any("X-Frame-Options" in t for t in titles)


def test_headers_server_version_disclosure():
    mock_resp = _mock_response({"server": "nginx/1.18.0"})
    with patch("webshield.modules.headers.get_client") as mock_client:
        mock_client.return_value.__enter__.return_value.get.return_value = mock_resp
        findings = headers.scan("https://example.com")
    assert any("Server" in f.title for f in findings)


def test_headers_x_powered_by():
    mock_resp = _mock_response({"x-powered-by": "PHP/7.4.0"})
    with patch("webshield.modules.headers.get_client") as mock_client:
        mock_client.return_value.__enter__.return_value.get.return_value = mock_resp
        findings = headers.scan("https://example.com")
    assert any("X-Powered-By" in f.title for f in findings)


# ── Cookies module ────────────────────────────────────────────────────

def test_cookies_missing_secure_and_httponly():
    mock_resp = _mock_response(
        {"set-cookie": "sessionid=abc123; Path=/"},
        body=""
    )
    with patch("webshield.modules.cookies.get_client") as mock_client:
        mock_client.return_value.__enter__.return_value.get.return_value = mock_resp
        findings = cookies.scan("https://example.com")
    assert any("Secure" in f.title for f in findings)
    assert any("HttpOnly" in f.title for f in findings)


def test_cookies_all_flags_present():
    mock_resp = _mock_response(
        {"set-cookie": "session=xyz; Secure; HttpOnly; SameSite=Lax"},
        body=""
    )
    with patch("webshield.modules.cookies.get_client") as mock_client:
        mock_client.return_value.__enter__.return_value.get.return_value = mock_resp
        findings = cookies.scan("https://example.com")
    flag_issues = [f for f in findings if "Missing" in f.title]
    assert len(flag_issues) == 0


# ── CORS module ───────────────────────────────────────────────────────

def test_cors_wildcard():
    mock_resp = _mock_response({
        "access-control-allow-origin": "*",
        "content-type": "application/json"
    })
    with patch("webshield.modules.cors.get_client") as mock_client:
        mock_client.return_value.__enter__.return_value.get.return_value = mock_resp
        findings = cors.scan("https://example.com")
    assert any("Wildcard" in f.title for f in findings)


def test_cors_reflect_with_credentials():
    mock_resp = _mock_response({
        "access-control-allow-origin": "https://evil.com",
        "access-control-allow-credentials": "true",
    })
    with patch("webshield.modules.cors.get_client") as mock_client:
        mock_client.return_value.__enter__.return_value.get.return_value = mock_resp
        findings = cors.scan("https://example.com")
    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(critical) > 0


# ── CSP module ────────────────────────────────────────────────────────

def test_csp_missing():
    mock_resp = _mock_response({"content-type": "text/html"})
    with patch("webshield.modules.csp.get_client") as mock_client:
        mock_client.return_value.__enter__.return_value.get.return_value = mock_resp
        findings = csp.scan("https://example.com")
    assert any("CSP" in f.title and "Not Set" in f.title for f in findings)


def test_csp_unsafe_inline():
    mock_resp = _mock_response({
        "content-security-policy": "default-src 'self'; script-src 'unsafe-inline'"
    })
    with patch("webshield.modules.csp.get_client") as mock_client:
        mock_client.return_value.__enter__.return_value.get.return_value = mock_resp
        findings = csp.scan("https://example.com")
    assert any("unsafe-inline" in f.title for f in findings)


def test_csp_good_policy():
    mock_resp = _mock_response({
        "content-security-policy": (
            "default-src 'self'; script-src 'self'; "
            "object-src 'none'; base-uri 'self'; frame-ancestors 'self'"
        )
    })
    with patch("webshield.modules.csp.get_client") as mock_client:
        mock_client.return_value.__enter__.return_value.get.return_value = mock_resp
        findings = csp.scan("https://example.com")
    critical_high = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    assert len(critical_high) == 0
