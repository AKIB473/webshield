"""Tests for v1.0.1 new modules and features."""
import json
import pytest
from unittest.mock import patch, MagicMock
import httpx

from webshield.core.models import Finding, ScanResult, Severity
from webshield.modules import clickjacking, mixed_content, sri_check
from webshield.reporter.sarif import save_sarif
from webshield.reporter.json_out import ci_exit_code


def _mock_resp(headers_dict: dict, status: int = 200,
               body: str = "<html></html>", url: str = "https://example.com"):
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status
    resp.headers = httpx.Headers(headers_dict)
    resp.text = body
    resp.content = body.encode()
    resp.cookies = httpx.Cookies()
    resp.url = httpx.URL(url)
    return resp


# ── Clickjacking ──────────────────────────────────────────────────────

def test_clickjacking_missing():
    mock_resp = _mock_resp({"content-type": "text/html"})
    with patch("webshield.modules.clickjacking.get_client") as mc:
        mc.return_value.__enter__.return_value.get.return_value = mock_resp
        findings = clickjacking.scan("https://example.com")
    assert any("Clickjacking" in f.title for f in findings)
    assert findings[0].severity == Severity.MEDIUM


def test_clickjacking_xfo_present():
    mock_resp = _mock_resp({"x-frame-options": "SAMEORIGIN"})
    with patch("webshield.modules.clickjacking.get_client") as mc:
        mc.return_value.__enter__.return_value.get.return_value = mock_resp
        findings = clickjacking.scan("https://example.com")
    assert not any("Missing" in f.title for f in findings)


def test_clickjacking_xfo_allowall():
    mock_resp = _mock_resp({"x-frame-options": "ALLOWALL"})
    with patch("webshield.modules.clickjacking.get_client") as mc:
        mc.return_value.__enter__.return_value.get.return_value = mock_resp
        findings = clickjacking.scan("https://example.com")
    assert any("ALLOWALL" in f.title for f in findings)
    assert findings[0].severity == Severity.HIGH


def test_clickjacking_csp_frame_ancestors():
    mock_resp = _mock_resp({
        "content-security-policy": "default-src 'self'; frame-ancestors 'self'"
    })
    with patch("webshield.modules.clickjacking.get_client") as mc:
        mc.return_value.__enter__.return_value.get.return_value = mock_resp
        findings = clickjacking.scan("https://example.com")
    assert not any("Missing" in f.title for f in findings)


# ── Mixed Content ─────────────────────────────────────────────────────

def test_mixed_content_active():
    body = '<html><script src="http://cdn.example.com/app.js"></script></html>'
    mock_resp = _mock_resp({"content-type": "text/html"}, body=body,
                           url="https://example.com")
    with patch("webshield.modules.mixed_content.get_client") as mc:
        mc.return_value.__enter__.return_value.get.return_value = mock_resp
        findings = mixed_content.scan("https://example.com")
    assert any("Active Mixed Content" in f.title for f in findings)
    assert findings[0].severity == Severity.HIGH


def test_mixed_content_passive():
    body = '<html><img src="http://example.com/photo.jpg"></html>'
    mock_resp = _mock_resp({"content-type": "text/html"}, body=body,
                           url="https://example.com")
    with patch("webshield.modules.mixed_content.get_client") as mc:
        mc.return_value.__enter__.return_value.get.return_value = mock_resp
        findings = mixed_content.scan("https://example.com")
    assert any("Passive" in f.title for f in findings)


def test_mixed_content_http_skipped():
    # Mixed content only matters for HTTPS
    mock_resp = _mock_resp({}, body="<script src='http://evil.com/x.js'>")
    with patch("webshield.modules.mixed_content.get_client") as mc:
        mc.return_value.__enter__.return_value.get.return_value = mock_resp
        findings = mixed_content.scan("http://example.com")
    assert len(findings) == 0


# ── SRI Check ─────────────────────────────────────────────────────────

def test_sri_missing_on_cdn():
    body = '<script src="https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js"></script>'
    mock_resp = _mock_resp({}, body=body)
    with patch("webshield.modules.sri_check.get_client") as mc:
        mc.return_value.__enter__.return_value.get.return_value = mock_resp
        findings = sri_check.scan("https://example.com")
    assert any("SRI" in f.title for f in findings)


def test_sri_present():
    body = (
        '<script src="https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js" '
        'integrity="sha256-abc123" crossorigin="anonymous"></script>'
    )
    mock_resp = _mock_resp({}, body=body)
    with patch("webshield.modules.sri_check.get_client") as mc:
        mc.return_value.__enter__.return_value.get.return_value = mock_resp
        findings = sri_check.scan("https://example.com")
    assert not any("SRI" in f.title and "Missing" in f.title for f in findings)


# ── SARIF Reporter ────────────────────────────────────────────────────

def test_sarif_output(tmp_path):
    result = ScanResult(target="https://example.com")
    result.add_finding(Finding(
        title="Test Critical Finding",
        severity=Severity.CRITICAL,
        description="A critical issue was found.",
        evidence="Evidence here",
        remediation="Fix it now",
        reference="https://owasp.org",
        cvss=9.8,
        module="headers",
    ))
    result.add_finding(Finding(
        title="Info Finding",
        severity=Severity.INFO,
        description="Just info.",
        module="ssl_tls",
    ))
    result.scan_duration = 1.5

    sarif_path = str(tmp_path / "results.sarif")
    save_sarif(result, sarif_path)

    with open(sarif_path) as f:
        sarif = json.load(f)

    assert sarif["version"] == "2.1.0"
    runs = sarif["runs"]
    assert len(runs) == 1
    assert runs[0]["tool"]["driver"]["name"] == "WebShield"

    # INFO findings should be excluded from SARIF
    sarif_results = runs[0]["results"]
    assert len(sarif_results) == 1
    assert sarif_results[0]["level"] == "error"


# ── CI exit code ──────────────────────────────────────────────────────

def test_ci_exit_pass():
    r = ScanResult(target="https://example.com")
    r.add_finding(Finding(severity=Severity.LOW))
    assert ci_exit_code(r, "high") == 0


def test_ci_exit_fail_on_high():
    r = ScanResult(target="https://example.com")
    r.add_finding(Finding(severity=Severity.HIGH))
    assert ci_exit_code(r, "high") == 1


def test_ci_exit_fail_on_critical_only():
    r = ScanResult(target="https://example.com")
    r.add_finding(Finding(severity=Severity.HIGH))
    assert ci_exit_code(r, "critical") == 0  # High not critical


def test_ci_exit_fail_medium():
    r = ScanResult(target="https://example.com")
    r.add_finding(Finding(severity=Severity.MEDIUM))
    assert ci_exit_code(r, "medium") == 1
