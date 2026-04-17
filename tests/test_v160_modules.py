"""Tests for v1.6.0 and v1.7.0 modules."""
import pytest
from unittest.mock import patch, MagicMock
import httpx

from webshield.core.models import Severity
from webshield.modules import (
    source_code_disclosure, bypass_403, pii_detection,
    spring_actuator, http_parameter_pollution, cve_checks,
    websocket_security, default_credentials, exposed_panels,
    evasion_scan, openapi_scan, xxe_oob,
)


def _mock(headers=None, status=200, body="<html></html>", url="https://example.com"):
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status
    resp.headers = httpx.Headers(headers or {"content-type": "text/html"})
    resp.text = body
    resp.content = body.encode()
    resp.cookies = httpx.Cookies()
    return resp


# ── source_code_disclosure ───────────────────────────────────────────

def test_git_head_exposed():
    git_body = "ref: refs/heads/main\n"
    mock_git  = _mock(body=git_body)
    mock_404  = _mock(status=404, body="Not Found")
    with patch("webshield.modules.source_code_disclosure.get_client") as mc:
        mc.return_value.__enter__.return_value.get.side_effect = [
            mock_git, mock_404, mock_404, mock_404, mock_404,
            mock_404, mock_404, mock_404, mock_404, mock_404,
        ]
        findings = source_code_disclosure.scan("https://example.com")
    assert any(".git" in f.title for f in findings)
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_source_map_exposed():
    page_body  = "var x=1;\n//# sourceMappingURL=app.js.map"
    map_body   = '{"version":3,"sources":["src/app.js"],"mappings":"AAAA"}'
    mock_page  = _mock(body=page_body, headers={"content-type": "application/javascript"})
    mock_map   = _mock(body=map_body,  headers={"content-type": "application/json"})
    mock_404   = _mock(status=404, body="")
    with patch("webshield.modules.source_code_disclosure.get_client") as mc:
        client = mc.return_value.__enter__.return_value
        # VCS checks all 404, then page load returns source map hint, map request succeeds
        client.get.side_effect = [mock_404] * 5 + [mock_page, mock_map] + [mock_404] * 20
        findings = source_code_disclosure.scan("https://example.com/app.js")
    assert any("Source Map" in f.title for f in findings)


def test_source_code_clean():
    mock_404 = _mock(status=404, body="Not Found")
    mock_ok  = _mock(body="<html>Normal page</html>")
    with patch("webshield.modules.source_code_disclosure.get_client") as mc:
        mc.return_value.__enter__.return_value.get.return_value = mock_404
        findings = source_code_disclosure.scan("https://example.com")
    assert len(findings) == 0


# ── bypass_403 ──────────────────────────────────────────────────────

def test_bypass_403_verb_tampering():
    mock_403  = _mock(status=403, body="Forbidden")
    mock_200  = _mock(status=200, body="<html><h1>Admin Panel</h1></html>")
    with patch("webshield.modules.bypass_403.get_client") as mc:
        client = mc.return_value.__enter__.return_value
        client.get.return_value     = mock_403
        client.request.return_value = mock_200
        findings = bypass_403.scan("https://example.com")
    assert any("Verb Tampering" in f.title or "bypass" in f.title.lower() for f in findings)
    assert any(f.severity == Severity.HIGH for f in findings)


def test_bypass_403_no_protected_paths():
    mock_200 = _mock(status=200, body="<html>Public page</html>")
    with patch("webshield.modules.bypass_403.get_client") as mc:
        mc.return_value.__enter__.return_value.get.return_value = mock_200
        findings = bypass_403.scan("https://example.com")
    assert len(findings) == 0


# ── pii_detection ────────────────────────────────────────────────────

def test_pii_ssn_detected():
    body = '{"users": [{"name": "Alice", "ssn": "123-45-6789"}, {"name": "Bob", "ssn": "987-65-4320"}]}'
    mock = _mock(body=body)
    with patch("webshield.modules.pii_detection.get_client") as mc:
        mc.return_value.__enter__.return_value.get.return_value = mock
        findings = pii_detection.scan("https://example.com")
    assert any("SSN" in f.title for f in findings)
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_pii_credit_card_detected():
    # 4532015112830366 is a valid Visa test number (Luhn-valid)
    body = '{"payment": {"card": "4532015112830366", "exp": "12/25"}}'
    mock = _mock(body=body)
    with patch("webshield.modules.pii_detection.get_client") as mc:
        mc.return_value.__enter__.return_value.get.return_value = mock
        findings = pii_detection.scan("https://example.com")
    assert any("Credit Card" in f.title for f in findings)


def test_pii_bulk_emails():
    emails = " ".join([f"user{i}@company.com" for i in range(10)])
    body = f"<html>{emails}</html>"
    mock = _mock(body=body)
    with patch("webshield.modules.pii_detection.get_client") as mc:
        mc.return_value.__enter__.return_value.get.return_value = mock
        findings = pii_detection.scan("https://example.com")
    assert any("Email" in f.title for f in findings)


def test_pii_clean():
    mock = _mock(body="<html><p>No sensitive data here</p></html>")
    with patch("webshield.modules.pii_detection.get_client") as mc:
        mc.return_value.__enter__.return_value.get.return_value = mock
        findings = pii_detection.scan("https://example.com")
    pii = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    assert len(pii) == 0


# ── spring_actuator ──────────────────────────────────────────────────

def test_actuator_env_exposed():
    body = '{"activeProfiles":["production"],"propertySources":[{"name":"systemEnvironment"}]}'
    mock_env = _mock(body=body, headers={"content-type": "application/json"})
    mock_404 = _mock(status=404, body="")
    with patch("webshield.modules.spring_actuator.get_client") as mc:
        client = mc.return_value.__enter__.return_value
        client.get.side_effect = [mock_404, mock_env] + [mock_404] * 30
        client.post.return_value = mock_404
        findings = spring_actuator.scan("https://example.com")
    assert any("env" in f.title.lower() or "Environment" in f.title for f in findings)
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_actuator_heapdump_exposed():
    mock_heap = _mock(
        body="heap_data",
        headers={"content-type": "application/octet-stream"},
        status=200
    )
    mock_404 = _mock(status=404, body="")
    with patch("webshield.modules.spring_actuator.get_client") as mc:
        client = mc.return_value.__enter__.return_value
        client.get.side_effect = [mock_heap] + [mock_404] * 30
        client.post.return_value = mock_404
        findings = spring_actuator.scan("https://example.com")
    assert any("Heap" in f.title or "heapdump" in f.title.lower() for f in findings)


def test_actuator_clean():
    mock_404 = _mock(status=404, body="")
    with patch("webshield.modules.spring_actuator.get_client") as mc:
        mc.return_value.__enter__.return_value.get.return_value = mock_404
        mc.return_value.__enter__.return_value.post.return_value = mock_404
        findings = spring_actuator.scan("https://example.com")
    assert len(findings) == 0


# ── http_parameter_pollution ─────────────────────────────────────────

def test_hpp_second_value_reflected():
    mock_base = _mock(body="<html>Results for: original</html>")
    mock_dup  = _mock(body="<html>Results for: INJECTED</html>")
    with patch("webshield.modules.http_parameter_pollution.get_client") as mc:
        mc.return_value.__enter__.return_value.get.side_effect = [mock_base, mock_dup] + [mock_dup] * 10
        findings = http_parameter_pollution.scan("https://example.com?q=original")
    assert any("Pollution" in f.title or "HPP" in f.title for f in findings)


def test_hpp_no_params():
    mock = _mock(body="<html>Normal</html>")
    with patch("webshield.modules.http_parameter_pollution.get_client") as mc:
        mc.return_value.__enter__.return_value.get.return_value = mock
        findings = http_parameter_pollution.scan("https://example.com")
    # With no params, HPP module tries probe params
    # Should not crash
    assert isinstance(findings, list)


# ── cve_checks ───────────────────────────────────────────────────────

def test_cve_grafana_path_traversal():
    passwd_body = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:"
    mock_passwd = _mock(body=passwd_body, status=200)
    mock_404    = _mock(status=404, body="Not Found")
    with patch("webshield.modules.cve_checks.get_client") as mc:
        client = mc.return_value.__enter__.return_value
        # First CVE check that matches: Grafana path traversal
        responses = [mock_404] * 3 + [mock_passwd] + [mock_404] * 20
        client.get.side_effect  = responses
        client.post.return_value = mock_404
        findings = cve_checks.scan("https://example.com")
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_cve_clean():
    mock_200 = _mock(status=200, body="<html>Normal site</html>")
    with patch("webshield.modules.cve_checks.get_client") as mc:
        mc.return_value.__enter__.return_value.get.return_value  = mock_200
        mc.return_value.__enter__.return_value.post.return_value = mock_200
        findings = cve_checks.scan("https://example.com")
    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(critical) == 0


# ── websocket_security ───────────────────────────────────────────────

def test_websocket_insecure_ws_on_https():
    body = "<html><script>const ws = new WebSocket('ws://example.com/chat');</script></html>"
    mock = _mock(body=body)
    with patch("webshield.modules.websocket_security.get_client") as mc:
        mc.return_value.__enter__.return_value.get.return_value = mock
        with patch("webshield.modules.websocket_security._make_ws_handshake_request",
                   return_value={"status": 404, "headers": "", "upgraded": False}):
            findings = websocket_security.scan("https://example.com")
    assert any("ws://" in f.title or "Insecure WebSocket" in f.title or
               "Downgrade" in f.title for f in findings)
    assert any(f.severity == Severity.HIGH for f in findings)


def test_websocket_clean():
    mock = _mock(body="<html><p>No WebSocket here</p></html>")
    with patch("webshield.modules.websocket_security.get_client") as mc:
        mc.return_value.__enter__.return_value.get.return_value = mock
        with patch("webshield.modules.websocket_security._make_ws_handshake_request",
                   return_value={"status": 0, "headers": "", "upgraded": False}):
            findings = websocket_security.scan("https://example.com")
    high_plus = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    assert len(high_plus) == 0


# ── default_credentials ──────────────────────────────────────────────

def test_default_creds_grafana():
    detect_body = "<html><title>Grafana</title></html>"
    login_ok    = '{"message":"Logged in"}'
    mock_detect = _mock(body=detect_body, status=200)
    mock_login  = _mock(body=login_ok, status=200)
    mock_404    = _mock(status=404, body="")
    with patch("webshield.modules.default_credentials.get_client") as mc:
        client = mc.return_value.__enter__.return_value
        client.get.side_effect  = [mock_404, mock_detect] + [mock_404] * 20
        client.post.return_value = mock_login
        findings = default_credentials.scan("https://example.com")
    assert any("Default Credentials" in f.title for f in findings)
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_default_creds_clean():
    mock_404 = _mock(status=404, body="")
    with patch("webshield.modules.default_credentials.get_client") as mc:
        mc.return_value.__enter__.return_value.get.return_value  = mock_404
        mc.return_value.__enter__.return_value.post.return_value = mock_404
        findings = default_credentials.scan("https://example.com")
    assert len(findings) == 0


# ── exposed_panels ───────────────────────────────────────────────────

def test_exposed_grafana_panel():
    mock_grafana = _mock(body="<html><title>Grafana</title><h1>Grafana Dashboard</h1></html>")
    mock_404     = _mock(status=404, body="")
    with patch("webshield.modules.exposed_panels.get_client") as mc:
        client = mc.return_value.__enter__.return_value
        client.get.side_effect = [mock_404, mock_grafana] + [mock_404] * 40
        findings = exposed_panels.scan("https://example.com")
    assert any("Grafana" in f.title for f in findings)


def test_exposed_env_file():
    mock_env = _mock(body="DB_PASSWORD=supersecret\nSECRET_KEY=abc123\nAPP_KEY=base64:xyz")
    mock_404 = _mock(status=404, body="")
    with patch("webshield.modules.exposed_panels.get_client") as mc:
        client = mc.return_value.__enter__.return_value
        # .env is near the end of the PANELS list — return 404 for all before it
        client.get.side_effect = [mock_404] * 24 + [mock_env] + [mock_404] * 10
        findings = exposed_panels.scan("https://example.com")
    assert any(".env" in f.title for f in findings)
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_exposed_panels_clean():
    mock_404 = _mock(status=404, body="")
    with patch("webshield.modules.exposed_panels.get_client") as mc:
        mc.return_value.__enter__.return_value.get.return_value = mock_404
        findings = exposed_panels.scan("https://example.com")
    assert len(findings) == 0


# ── evasion_scan ─────────────────────────────────────────────────────

def test_evasion_sqli_bypass():
    sql_error = "You have an error in your SQL syntax near 'INJECTED'"
    mock_base = _mock(body="<html>Normal results</html>")
    mock_sqli = _mock(body=sql_error)
    with patch("webshield.modules.evasion_scan.get_client") as mc:
        client = mc.return_value.__enter__.return_value
        client.get.side_effect = [mock_base] + [mock_sqli] * 30
        findings = evasion_scan.scan("https://example.com?id=1")
    assert any("SQLi" in f.title or "WAF Bypass" in f.title for f in findings)


def test_evasion_no_params():
    findings = evasion_scan.scan("https://example.com")
    assert len(findings) == 0


# ── openapi_scan ─────────────────────────────────────────────────────

def test_openapi_spec_found():
    spec = '{"openapi":"3.0.0","info":{"title":"Test"},"paths":{"/users":{"get":{}},"/admin":{"get":{}}}}'
    mock_spec = _mock(body=spec, headers={"content-type": "application/json"})
    mock_200  = _mock(body='{"users":[]}', status=200)
    mock_404  = _mock(status=404, body="")
    with patch("webshield.modules.openapi_scan.get_client") as mc:
        client = mc.return_value.__enter__.return_value
        client.get.side_effect = [mock_spec] + [mock_200] * 20
        client.request.return_value = mock_404
        findings = openapi_scan.scan("https://example.com")
    assert any("OpenAPI" in f.title or "Swagger" in f.title for f in findings)
    assert any("Unauthenticated" in f.title for f in findings)


def test_openapi_no_spec():
    mock_404 = _mock(status=404, body="")
    with patch("webshield.modules.openapi_scan.get_client") as mc:
        mc.return_value.__enter__.return_value.get.return_value = mock_404
        findings = openapi_scan.scan("https://example.com")
    assert len(findings) == 0


# ── xxe_oob ──────────────────────────────────────────────────────────

def test_xxe_oob_passwd():
    passwd = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:"
    mock_xxe = _mock(body=f"<result>{passwd}</result>", status=200)
    with patch("webshield.modules.xxe_oob.get_client") as mc:
        mc.return_value.__enter__.return_value.post.return_value = mock_xxe
        findings = xxe_oob.scan("https://example.com")
    assert any("XXE" in f.title for f in findings)
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_xxe_oob_error_based():
    xml_err = "XMLSyntaxError: entity 'xxe' not defined"
    mock_err = _mock(body=xml_err, status=400)
    mock_ok  = _mock(body="<result/>", status=200)
    with patch("webshield.modules.xxe_oob.get_client") as mc:
        client = mc.return_value.__enter__.return_value
        # First two payloads return no passwd, third returns XML error
        client.post.side_effect = [mock_ok, mock_ok, mock_err] + [mock_ok] * 30
        findings = xxe_oob.scan("https://example.com")
    assert any("XXE" in f.title for f in findings)


def test_xxe_oob_clean():
    mock_415 = _mock(status=415, body="Unsupported Media Type")
    with patch("webshield.modules.xxe_oob.get_client") as mc:
        mc.return_value.__enter__.return_value.post.return_value = mock_415
        findings = xxe_oob.scan("https://example.com")
    assert len(findings) == 0


# ── Module count & import checks ─────────────────────────────────────

def test_v170_module_count():
    from webshield.core.scanner import ALL_MODULES
    assert len(ALL_MODULES) >= 60
    for mod in ["source_code_disclosure", "bypass_403", "pii_detection",
                "spring_actuator", "http_parameter_pollution", "cve_checks",
                "websocket_security", "default_credentials", "exposed_panels",
                "evasion_scan", "openapi_scan", "xxe_oob"]:
        assert mod in ALL_MODULES, f"Missing: {mod}"


def test_v170_all_importable():
    import importlib
    from webshield.core.scanner import ALL_MODULES
    failed = []
    for mod in ALL_MODULES:
        try:
            importlib.import_module(f"webshield.modules.{mod}")
        except Exception as e:
            failed.append(f"{mod}: {e}")
    assert failed == [], f"Import failures: {failed}"
