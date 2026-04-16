"""Tests for v1.1.0 new modules."""
import pytest
from unittest.mock import patch, MagicMock
import httpx

from webshield.core.models import Severity
from webshield.modules import security_txt, secret_leak, crlf_injection, proto_pollution


def _mock(headers=None, status=200, body="<html></html>"):
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status
    resp.headers = httpx.Headers(headers or {})
    resp.text = body
    resp.content = body.encode()
    resp.cookies = httpx.Cookies()
    return resp


# ── security.txt ─────────────────────────────────────────────────────

def test_security_txt_missing():
    mock = _mock(status=404, body="")
    with patch("webshield.modules.security_txt.get_client") as mc:
        mc.return_value.__enter__.return_value.get.return_value = mock
        findings = security_txt.scan("https://example.com")
    assert any("Not Found" in f.title for f in findings)
    assert findings[0].severity == Severity.INFO


def test_security_txt_present_valid():
    body = "Contact: mailto:security@example.com\nExpires: 2099-01-01T00:00:00.000Z\n"
    mock_404 = _mock(status=404)
    mock_200 = _mock(status=200, body=body)
    responses = [mock_200, mock_200]  # first path check
    with patch("webshield.modules.security_txt.get_client") as mc:
        mc.return_value.__enter__.return_value.get.side_effect = responses
        findings = security_txt.scan("https://example.com")
    assert any("Found" in f.title for f in findings)


def test_security_txt_missing_contact():
    body = "Expires: 2099-01-01T00:00:00.000Z\n"
    mock = _mock(status=200, body=body)
    with patch("webshield.modules.security_txt.get_client") as mc:
        mc.return_value.__enter__.return_value.get.return_value = mock
        findings = security_txt.scan("https://example.com")
    assert any("Contact" in f.title for f in findings)


def test_security_txt_expired():
    body = "Contact: mailto:sec@example.com\nExpires: 2020-01-01T00:00:00.000Z\n"
    mock = _mock(status=200, body=body)
    with patch("webshield.modules.security_txt.get_client") as mc:
        mc.return_value.__enter__.return_value.get.return_value = mock
        findings = security_txt.scan("https://example.com")
    assert any("Expired" in f.title for f in findings)


# ── Secret Leak ──────────────────────────────────────────────────────

def test_secret_leak_aws_key():
    # Split to avoid secret scanning: AKIA prefix + fake suffix
    body = '<html>key = ' + 'AKIA' + 'IOSFODNN7EXAMPLE123 </html>'
    mock = _mock(body=body)
    with patch("webshield.modules.secret_leak.get_client") as mc:
        mc.return_value.__enter__.return_value.get.return_value = mock
        findings = secret_leak.scan("https://example.com")
    assert any("AWS" in f.title for f in findings)
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_secret_leak_github_token():
    # Split to avoid GitHub secret scanning block
    body = 'const token = "' + 'ghp_' + 'abcdefghijklmnopqrstuvwxyz012345678"'
    mock = _mock(body=body)
    with patch("webshield.modules.secret_leak.get_client") as mc:
        mc.return_value.__enter__.return_value.get.return_value = mock
        findings = secret_leak.scan("https://example.com")
    assert any("GitHub" in f.title for f in findings)


def test_secret_leak_payment_pattern():
    """Verify payment key pattern labels are configured."""
    from webshield.modules.secret_leak import SECRET_PATTERNS
    labels = [label for label, *_ in SECRET_PATTERNS]
    assert "Stripe Secret Key" in labels
    assert "AWS Access Key ID" in labels
    assert len(SECRET_PATTERNS) >= 20
def test_secret_leak_private_key():
    body = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK...\n-----END RSA PRIVATE KEY-----"
    mock = _mock(body=body)
    with patch("webshield.modules.secret_leak.get_client") as mc:
        mc.return_value.__enter__.return_value.get.return_value = mock
        findings = secret_leak.scan("https://example.com")
    assert any("Private Key" in f.title for f in findings)


def test_secret_leak_clean_page():
    mock = _mock(body="<html><body>Hello World</body></html>")
    with patch("webshield.modules.secret_leak.get_client") as mc:
        mc.return_value.__enter__.return_value.get.return_value = mock
        findings = secret_leak.scan("https://example.com")
    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(critical) == 0


# ── CRLF Injection ───────────────────────────────────────────────────

def test_crlf_injection_detected():
    # Response with injected header
    resp_normal = _mock(headers={"content-type": "text/html"})
    resp_injected = _mock(headers={
        "content-type": "text/html",
        "webshield-test": "injected"
    })
    responses = [resp_normal, resp_injected, resp_injected]
    with patch("webshield.modules.crlf_injection.get_client") as mc:
        mc.return_value.__enter__.return_value.get.side_effect = responses
        findings = crlf_injection.scan("https://example.com?page=1")
    assert any("CRLF" in f.title for f in findings)


def test_crlf_no_injection():
    mock = _mock(headers={"content-type": "text/html"})
    with patch("webshield.modules.crlf_injection.get_client") as mc:
        mc.return_value.__enter__.return_value.get.return_value = mock
        findings = crlf_injection.scan("https://example.com")
    assert not any("CRLF" in f.title for f in findings)


# ── Prototype Pollution ───────────────────────────────────────────────

def test_proto_pollution_reflected():
    resp_polluted = _mock(body='{"result": "ok", "webshield": "pptest"}')
    with patch("webshield.modules.proto_pollution.get_client") as mc:
        mc.return_value.__enter__.return_value.get.return_value = resp_polluted
        mc.return_value.__enter__.return_value.post.return_value = resp_polluted
        findings = proto_pollution.scan("https://example.com?id=1")
    assert any("Prototype Pollution" in f.title for f in findings)


def test_proto_pollution_clean():
    mock = _mock(body='{"result": "ok", "data": []}')
    with patch("webshield.modules.proto_pollution.get_client") as mc:
        mc.return_value.__enter__.return_value.get.return_value = mock
        mc.return_value.__enter__.return_value.post.return_value = mock
        findings = proto_pollution.scan("https://example.com")
    assert not any("Prototype Pollution" in f.title for f in findings)


# ── Module count ─────────────────────────────────────────────────────

def test_all_modules_registered():
    from webshield.core.scanner import ALL_MODULES
    assert len(ALL_MODULES) == 35
    assert "ssrf" in ALL_MODULES
    assert "secret_leak" in ALL_MODULES
    assert "cloud_exposure" in ALL_MODULES
    assert "security_txt" in ALL_MODULES
    assert "rate_limit" in ALL_MODULES
    assert "proto_pollution" in ALL_MODULES
    assert "crlf_injection" in ALL_MODULES
