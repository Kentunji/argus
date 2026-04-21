"""JSON reporter — writes a machine-readable scan report."""

from __future__ import annotations

import json
from pathlib import Path

from src.reporters.base import Reporter
from src.scan_result import ScanResult


def _serialize(obj):
    if hasattr(obj, "isoformat"):
        return obj.isoformat()
    if hasattr(obj, "value"):
        return obj.value
    return str(obj)


class JsonReporter(Reporter):
    def __init__(self, output_dir: Path) -> None:
        self._output_dir = output_dir

    def render(self, result: ScanResult) -> str:
        self._output_dir.mkdir(parents=True, exist_ok=True)
        timestamp = result.started_at.strftime("%Y%m%d_%H%M%S")
        path = self._output_dir / f"scan_{timestamp}.json"

        payload = {
            "scan": {
                "target": result.target,
                "started_at": result.started_at.isoformat(),
                "completed_at": result.completed_at.isoformat() if result.completed_at else None,
                "duration_seconds": result.duration_seconds,
                "urls_visited": result.urls_visited,
                "forms_tested": result.forms_tested,
                "detectors_run": result.detectors_run,
                "errors": result.errors,
                "totals_by_severity": result.finding_count_by_severity,
                "executive_summary": result.executive_summary,
            },
            "findings": [
                {
                    "id": f.id,
                    "detector": f.detector,
                    "type": f.type,
                    "severity": f.severity.value,
                    "confidence": f.confidence.value,
                    "cwe": f.cwe,
                    "owasp": f.owasp,
                    "discovered_at": f.discovered_at.isoformat(),
                    "evidence": {
                        "method": f.evidence.method,
                        "url": f.evidence.url,
                        "parameter": f.evidence.parameter,
                        "payload": f.evidence.payload,
                        "indicator": f.evidence.indicator,
                        "response_snippet": f.evidence.response_snippet,
                    },
                    "remediation": f.remediation,
                    "triage": {
                        "confidence": f.triage.confidence.value,
                        "explanation": f.triage.explanation,
                        "tailored_remediation": f.triage.tailored_remediation,
                        "is_false_positive": f.triage.is_false_positive,
                        "model": f.triage.model,
                    } if f.triage else None,
                }
                for f in result.findings
            ],
        }

        path.write_text(json.dumps(payload, indent=2, default=_serialize))
        return str(path)

