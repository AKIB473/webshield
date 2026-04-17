"""
Core data models — Finding, ScanResult, Severity
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional
import uuid


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"

    @property
    def score_penalty(self) -> int:
        return {
            "CRITICAL": 25,
            "HIGH":     15,
            "MEDIUM":    8,
            "LOW":       3,
            "INFO":      0,
        }[self.value]

    @property
    def color(self) -> str:
        return {
            "CRITICAL": "bold red",
            "HIGH":     "red",
            "MEDIUM":   "yellow",
            "LOW":      "cyan",
            "INFO":     "bright_black",
        }[self.value]

    @property
    def emoji(self) -> str:
        return {
            "CRITICAL": "🔴",
            "HIGH":     "🟠",
            "MEDIUM":   "🟡",
            "LOW":      "🔵",
            "INFO":     "⚪",
        }[self.value]


@dataclass
class Finding:
    """A single security finding."""
    id:          str       = field(default_factory=lambda: uuid.uuid4().hex[:8])
    title:       str       = ""
    severity:    Severity  = Severity.INFO
    description: str       = ""
    evidence:    str       = ""
    remediation: str       = ""
    code_fix:    str       = ""
    reference:   str       = ""
    module:      str       = ""
    cvss:        float     = 0.0

    def to_dict(self) -> dict:
        return {
            "id":          self.id,
            "title":       self.title,
            "severity":    self.severity.value,
            "description": self.description,
            "evidence":    self.evidence,
            "remediation": self.remediation,
            "code_fix":    self.code_fix,
            "reference":   self.reference,
            "module":      self.module,
            "cvss":        self.cvss,
        }


@dataclass
class ScanResult:
    """Aggregated results of a full WebShield scan."""
    target:        str           = ""
    findings:      List[Finding] = field(default_factory=list)
    score:         int           = 100
    grade:         str           = "A+"
    scan_duration: float         = 0.0
    modules_run:   List[str]     = field(default_factory=list)
    error:         Optional[str] = None

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)
        self.score = max(0, self.score - finding.severity.score_penalty)
        self.grade = self._compute_grade()

    def _compute_grade(self) -> str:
        s = self.score
        if s >= 95: return "A+"
        if s >= 90: return "A"
        if s >= 85: return "A-"
        if s >= 80: return "B+"
        if s >= 75: return "B"
        if s >= 70: return "B-"
        if s >= 65: return "C+"
        if s >= 60: return "C"
        if s >= 55: return "C-"
        if s >= 50: return "D+"
        if s >= 45: return "D"
        if s >= 40: return "D-"
        return "F"

    def by_severity(self, sev: Severity) -> List[Finding]:
        return [f for f in self.findings if f.severity == sev]

    def to_dict(self) -> dict:
        return {
            "target":        self.target,
            "score":         self.score,
            "grade":         self.grade,
            "scan_duration": self.scan_duration,
            "modules_run":   self.modules_run,
            "findings":      [f.to_dict() for f in self.findings],
            "summary": {
                "critical": len(self.by_severity(Severity.CRITICAL)),
                "high":     len(self.by_severity(Severity.HIGH)),
                "medium":   len(self.by_severity(Severity.MEDIUM)),
                "low":      len(self.by_severity(Severity.LOW)),
                "info":     len(self.by_severity(Severity.INFO)),
                "total":    len(self.findings),
            },
        }
