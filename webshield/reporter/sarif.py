"""
SARIF 2.1.0 Reporter (v1.2.0)
Outputs GitHub Code Scanning compatible SARIF for PR integration.
"""

from __future__ import annotations
import json
from pathlib import Path
from datetime import datetime, timezone
from typing import List
from webshield.core.models import ScanResult, Severity

SARIF_VERSION = "2.1.0"
TOOL_NAME = "WebShield"
TOOL_VERSION = "1.2.0"
TOOL_URL = "https://github.com/AKIB473/webshield"

SEV_TO_SARIF = {
    Severity.CRITICAL: "error",
    Severity.HIGH:     "error",
    Severity.MEDIUM:   "warning",
    Severity.LOW:      "note",
    Severity.INFO:     "none",
}

SEV_TO_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH:     "error",
    Severity.MEDIUM:   "warning",
    Severity.LOW:      "note",
    Severity.INFO:     "none",
}


def _make_rule(finding_id: str, title: str, description: str,
               reference: str, severity: Severity) -> dict:
    return {
        "id": finding_id,
        "name": title.replace(" ", "").replace(":", "").replace("-", ""),
        "shortDescription": {"text": title},
        "fullDescription": {"text": description},
        "helpUri": reference or TOOL_URL,
        "help": {"text": description, "markdown": f"**{title}**\n\n{description}"},
        "defaultConfiguration": {
            "level": SEV_TO_LEVEL[severity]
        },
        "properties": {
            "tags": ["security", "webshield"],
            "precision": "medium",
            "problem.severity": SEV_TO_SARIF[severity],
            "security-severity": str({
                Severity.CRITICAL: "9.0",
                Severity.HIGH:     "7.0",
                Severity.MEDIUM:   "5.0",
                Severity.LOW:      "3.0",
                Severity.INFO:     "0.0",
            }[severity]),
        },
    }


def save_sarif(result: ScanResult, output_path: str) -> None:
    rules = {}
    results = []

    for f in result.findings:
        if f.severity == Severity.INFO:
            continue  # Skip INFO in SARIF

        rule_id = f"WS-{f.id.upper()}"

        if rule_id not in rules:
            rules[rule_id] = _make_rule(
                rule_id, f.title, f.description,
                f.reference, f.severity
            )

        sarif_result = {
            "ruleId": rule_id,
            "level": SEV_TO_LEVEL[f.severity],
            "message": {
                "text": (
                    f"{f.description}"
                    + (f"\n\nEvidence: {f.evidence}" if f.evidence else "")
                    + (f"\n\nHow to fix: {f.remediation}" if f.remediation else "")
                )
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": result.target,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {"startLine": 1},
                    }
                }
            ],
            "properties": {
                "module": f.module,
                "cvss": f.cvss,
            },
        }
        results.append(sarif_result)

    sarif = {
        "version": SARIF_VERSION,
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": TOOL_VERSION,
                        "informationUri": TOOL_URL,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "automationDetails": {
                    "id": f"webshield/{result.target}/{datetime.now(timezone.utc).date()}"
                },
                "properties": {
                    "target": result.target,
                    "score": result.score,
                    "grade": result.grade,
                    "scan_duration": result.scan_duration,
                },
            }
        ],
    }

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(sarif, indent=2))
    print(f"[+] SARIF report saved to: {output_path}")
