"""
JSON Reporter — for CI/CD pipeline integration and programmatic use.
Exit code 1 if critical/high findings found — enables PR blocking.
"""

from __future__ import annotations
import json
import sys
from pathlib import Path
from datetime import datetime, timezone
from webshield.core.models import ScanResult, Severity


def save_json(result: ScanResult, output_path: str) -> None:
    data = result.to_dict()
    data["generated_at"] = datetime.now(timezone.utc).isoformat()
    data["tool"] = "WebShield"
    data["version"] = "1.0.0"

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2))
    print(f"[+] JSON report saved to: {output_path}")


def print_json(result: ScanResult) -> None:
    data = result.to_dict()
    data["generated_at"] = datetime.now(timezone.utc).isoformat()
    print(json.dumps(data, indent=2))


def ci_exit_code(result: ScanResult, fail_on: str = "high") -> int:
    """
    Return exit code for CI/CD:
      0 = pass
      1 = fail (found issues at or above threshold)
    """
    threshold_map = {
        "critical": [Severity.CRITICAL],
        "high":     [Severity.CRITICAL, Severity.HIGH],
        "medium":   [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM],
        "low":      [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW],
    }
    threshold_sevs = threshold_map.get(fail_on.lower(), threshold_map["high"])
    for finding in result.findings:
        if finding.severity in threshold_sevs:
            return 1
    return 0
