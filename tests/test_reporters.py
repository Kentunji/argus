"""Tests for terminal and JSON reporters."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console

from src.findings import Confidence, Evidence, Finding, Severity
from src.reporters.json_writer import JsonReporter
from src.reporters.terminal import TerminalReporter
from src.scan_result import ScanResult


def _sample_finding(idx: int = 1, severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        id=f"ARG-XSS-{idx:03d}",
        detector="xss",
        type="Reflected XSS",
        severity=severity,
        confidence=Confidence.LIKELY,
        cwe="CWE-79",
        owasp="A03:2021 Injection",
        evidence=Evidence(
            method="GET",
            url="http://target.test/?q=test",
            parameter="q",
            payload='"><argus>',
            indicator="Payload reflected raw",
            response_snippet="<html>...payload...</html>",
        ),
        remediation="Encode output.",
    )


def _sample_result(findings: list[Finding] | None = None) -> ScanResult:
    started = datetime(2026, 4, 19, 12, 0, 0, tzinfo=timezone.utc)
    completed = datetime(2026, 4, 19, 12, 0, 5, tzinfo=timezone.utc)
    return ScanResult(
        target="http://target.test",
        started_at=started,
        completed_at=completed,
        findings=findings or [],
        urls_visited=10,
        forms_tested=2,
        detectors_run=["xss", "sqli", "headers"],
    )


def test_terminal_reporter_handles_empty_findings() -> None:
    # Recording console — captures output without printing
    console = Console(record=True, file=open("/dev/null", "w"))
    TerminalReporter(console).render(_sample_result())
    output = console.export_text()
    assert "Argus Scan Summary" in output
    assert "No findings" in output


def test_terminal_reporter_renders_findings() -> None:
    console = Console(record=True, file=open("/dev/null", "w"))
    findings = [
        _sample_finding(1, Severity.HIGH),
        _sample_finding(2, Severity.MEDIUM),
    ]
    TerminalReporter(console).render(_sample_result(findings))
    output = console.export_text()
    assert "ARG-XSS-001" in output
    assert "ARG-XSS-002" in output
    assert "HIGH" in output
    assert "MEDIUM" in output


def test_json_reporter_writes_valid_json(tmp_path: Path) -> None:
    findings = [_sample_finding(1, Severity.HIGH)]
    result = _sample_result(findings)

    out_path = JsonReporter(tmp_path).render(result)
    assert Path(out_path).exists()

    payload = json.loads(Path(out_path).read_text())
    assert payload["scan"]["target"] == "http://target.test"
    assert payload["scan"]["urls_visited"] == 10
    assert payload["scan"]["totals_by_severity"] == {"HIGH": 1}
    assert len(payload["findings"]) == 1
    assert payload["findings"][0]["id"] == "ARG-XSS-001"
    assert payload["findings"][0]["evidence"]["parameter"] == "q"
