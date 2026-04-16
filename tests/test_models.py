"""Tests for core data models."""
import pytest
from webshield.core.models import Finding, ScanResult, Severity


def test_severity_score_penalty():
    assert Severity.CRITICAL.score_penalty == 25
    assert Severity.HIGH.score_penalty == 15
    assert Severity.INFO.score_penalty == 0


def test_scan_result_score_deduction():
    r = ScanResult(target="https://example.com")
    assert r.score == 100
    r.add_finding(Finding(severity=Severity.CRITICAL))
    assert r.score == 75
    r.add_finding(Finding(severity=Severity.HIGH))
    assert r.score == 60


def test_grade_computation():
    r = ScanResult(target="https://example.com")
    assert r.grade == "A+"
    r.score = 90; r.grade = r._compute_grade(); assert r.grade == "A"
    r.score = 50; r.grade = r._compute_grade(); assert r.grade == "D"
    r.score = 30; r.grade = r._compute_grade(); assert r.grade == "F"


def test_score_never_goes_below_zero():
    r = ScanResult(target="https://example.com")
    for _ in range(10):
        r.add_finding(Finding(severity=Severity.CRITICAL))
    assert r.score >= 0


def test_finding_to_dict():
    f = Finding(title="Test", severity=Severity.HIGH, cvss=7.5)
    d = f.to_dict()
    assert d["title"] == "Test"
    assert d["severity"] == "HIGH"
    assert d["cvss"] == 7.5


def test_scan_result_by_severity():
    r = ScanResult(target="https://example.com")
    r.add_finding(Finding(severity=Severity.CRITICAL))
    r.add_finding(Finding(severity=Severity.HIGH))
    r.add_finding(Finding(severity=Severity.HIGH))
    assert len(r.by_severity(Severity.CRITICAL)) == 1
    assert len(r.by_severity(Severity.HIGH)) == 2
    assert len(r.by_severity(Severity.LOW)) == 0


def test_scan_result_to_dict_summary():
    r = ScanResult(target="https://example.com")
    r.add_finding(Finding(severity=Severity.CRITICAL))
    r.add_finding(Finding(severity=Severity.MEDIUM))
    d = r.to_dict()
    assert d["summary"]["critical"] == 1
    assert d["summary"]["medium"] == 1
    assert d["summary"]["total"] == 2
