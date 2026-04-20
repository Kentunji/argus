"""Tests for the HTML reporter."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from src.findings import Confidence, Evidence, Finding, Severity, Triage
from src.reporters.html_writer import HtmlReporter, _render_markdown_basic
from src.scan_result import ScanResult


def _finding(idx: int = 1, with_triage: bool = True) -> Finding:
    triage = None
    if with_triage:
        triage = Triage(
            confidence=Confidence.CONFIRMED,
            explanation="Input is echoed unescaped into the page body.",
            tailored_remediation=(
                "Encode user input on output.\n\n"
                "```javascript\n"
                "res.send(escapeHtml(req.query.q));\n"
                "```\n"
            ),
            is_false_positive=False,
            model="deepseek-chat",
        )
    return Finding(
        id=f"ARG-XSS-{idx:03d}",
        detector="xss",
        type="Reflected XSS",
        severity=Severity.HIGH,
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
        triage=triage,
    )


def _result(findings, exec_summary: str = "") -> ScanResult:
    started = datetime(2026, 4, 20, 12, 0, 0, tzinfo=timezone.utc)
    completed = datetime(2026, 4, 20, 12, 0, 5, tzinfo=timezone.utc)
    return ScanResult(
        target="http://target.test",
        started_at=started,
        completed_at=completed,
        findings=findings,
        urls_visited=10,
        forms_tested=2,
        detectors_run=["xss", "sqli", "headers"],
        executive_summary=exec_summary,
    )


def test_html_reporter_writes_file(tmp_path: Path) -> None:
    path = HtmlReporter(tmp_path).render(_result([_finding(1)]))
    assert Path(path).exists()
    assert path.endswith(".html")


def test_html_reporter_contains_expected_content(tmp_path: Path) -> None:
    path = HtmlReporter(tmp_path).render(_result([_finding(1)], exec_summary="Test summary."))
    body = Path(path).read_text()

    # Document structure
    assert "<!DOCTYPE html>" in body
    assert "<title>Argus Scan Report" in body
    assert "http://target.test" in body
    # Finding
    assert "ARG-XSS-001" in body
    assert "Reflected XSS" in body
    assert "CWE-79" in body
    # Triage
    assert "AI Triage" in body
    assert "Input is echoed unescaped" in body
    # Code block from markdown-like triage output
    assert "escapeHtml" in body
    # Executive summary
    assert "Test summary" in body


def test_html_reporter_escapes_user_controlled_strings(tmp_path: Path) -> None:
    """User-controlled payloads in findings must not inject HTML into the report."""
    evil = _finding(1)
    evil = Finding(
        id=evil.id,
        detector=evil.detector,
        type=evil.type,
        severity=evil.severity,
        confidence=evil.confidence,
        cwe=evil.cwe,
        owasp=evil.owasp,
        evidence=Evidence(
            method="GET",
            url="http://target.test/?q=<script>alert(1)</script>",
            parameter="<script>x</script>",
            payload="<img src=x onerror=alert(1)>",
            indicator=evil.evidence.indicator,
            response_snippet=evil.evidence.response_snippet,
        ),
        remediation=evil.remediation,
        triage=evil.triage,
    )

    path = HtmlReporter(tmp_path).render(_result([evil]))
    body = Path(path).read_text()

    # Raw <script> from payload must NOT appear in the document
    assert "<script>alert(1)</script>" not in body
    assert "<img src=x onerror=alert(1)>" not in body
    # But the escaped version SHOULD appear
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in body


def test_html_reporter_handles_no_findings(tmp_path: Path) -> None:
    path = HtmlReporter(tmp_path).render(_result([]))
    body = Path(path).read_text()
    assert "No findings" in body


def test_html_reporter_marks_false_positives(tmp_path: Path) -> None:
    fp_finding = _finding(1)
    fp_finding = Finding(
        id=fp_finding.id,
        detector=fp_finding.detector,
        type=fp_finding.type,
        severity=fp_finding.severity,
        confidence=fp_finding.confidence,
        cwe=fp_finding.cwe,
        owasp=fp_finding.owasp,
        evidence=fp_finding.evidence,
        remediation=fp_finding.remediation,
        triage=Triage(
            confidence=Confidence.UNCERTAIN,
            explanation="Looks like an echo test page, not real reflection.",
            tailored_remediation="No action needed.",
            is_false_positive=True,
            model="deepseek-chat",
        ),
    )
    path = HtmlReporter(tmp_path).render(_result([fp_finding]))
    body = Path(path).read_text()
    assert "flagged as likely false positive" in body


def test_markdown_renderer_handles_fenced_code() -> None:
    text = "Do this:\n\n```python\nprint('hi')\n```\n\nThen that."
    rendered = _render_markdown_basic(text)
    assert "<pre>" in rendered
    assert "print(&#x27;hi&#x27;)" in rendered or "print('hi')" in rendered
    assert "Do this" in rendered
    assert "Then that" in rendered
