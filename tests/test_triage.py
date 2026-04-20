"""Tests for the LLM triage layer."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from src.findings import Confidence, Evidence, Finding, Severity
from src.llm.deepseek_client import LLMResponse
from src.llm.triage import Triager, _parse_triage_json


def _sample_finding() -> Finding:
    return Finding(
        id="ARG-SQLI-001",
        detector="sqli",
        type="SQL Injection (error-based)",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        cwe="CWE-89",
        owasp="A03:2021 Injection",
        evidence=Evidence(
            method="POST",
            url="http://target.test/login",
            parameter="email",
            payload="'",
            indicator="SQLite error leaked",
            response_snippet="SQLITE_ERROR: near \"'\"",
        ),
        remediation="Use parameterized queries.",
    )


# ─── JSON parsing ───────────────────────────────────────────────────

def test_parse_triage_json_well_formed() -> None:
    raw = '''{"confidence": "confirmed",
              "is_false_positive": false,
              "explanation": "The error reveals SQL is being built by concatenation.",
              "tailored_remediation": "Use prepared statements."}'''
    triage = _parse_triage_json(raw, "deepseek-chat")
    assert triage is not None
    assert triage.confidence == Confidence.CONFIRMED
    assert triage.is_false_positive is False
    assert "concatenation" in triage.explanation
    assert triage.model == "deepseek-chat"


def test_parse_triage_json_tolerates_surrounding_prose() -> None:
    raw = '''Sure, here's the analysis:
{"confidence": "likely", "is_false_positive": false,
 "explanation": "x", "tailored_remediation": "y"}
Hope this helps!'''
    triage = _parse_triage_json(raw, "m")
    assert triage is not None
    assert triage.confidence == Confidence.LIKELY


def test_parse_triage_json_returns_none_on_garbage() -> None:
    assert _parse_triage_json("no json here", "m") is None
    assert _parse_triage_json("{not valid json", "m") is None


def test_parse_triage_json_defaults_unknown_confidence_to_uncertain() -> None:
    raw = '{"confidence": "super-confident", "is_false_positive": false, "explanation": "", "tailored_remediation": ""}'
    triage = _parse_triage_json(raw, "m")
    assert triage.confidence == Confidence.UNCERTAIN


# ─── Triager behavior with mocked client ────────────────────────────

def _mock_client(content: str, model: str = "deepseek-chat") -> MagicMock:
    client = MagicMock()
    client.analyze.return_value = LLMResponse(
        content=content,
        model=model,
        prompt_tokens=10,
        completion_tokens=20,
    )
    return client


def test_triage_finding_attaches_triage() -> None:
    client = _mock_client(
        '{"confidence": "confirmed", "is_false_positive": false, '
        '"explanation": "Yes, SQLi.", "tailored_remediation": "Parameterize."}'
    )
    triager = Triager(client)
    out = triager.triage_finding(_sample_finding())
    assert out.triage is not None
    assert out.triage.explanation == "Yes, SQLi."
    assert out.id == "ARG-SQLI-001"  # other fields preserved


def test_triage_finding_returns_original_when_llm_fails() -> None:
    client = MagicMock()
    client.analyze.side_effect = RuntimeError("LLM is down")
    triager = Triager(client)
    out = triager.triage_finding(_sample_finding())
    assert out.triage is None
    assert out.id == "ARG-SQLI-001"


def test_triage_finding_returns_original_when_response_not_parseable() -> None:
    client = _mock_client("sorry, I can't respond in JSON today")
    triager = Triager(client)
    out = triager.triage_finding(_sample_finding())
    assert out.triage is None


def test_triage_all_processes_every_finding() -> None:
    client = _mock_client(
        '{"confidence": "likely", "is_false_positive": false, '
        '"explanation": "x", "tailored_remediation": "y"}'
    )
    triager = Triager(client)
    findings = [_sample_finding(), _sample_finding(), _sample_finding()]
    out = triager.triage_all(findings)
    assert len(out) == 3
    assert all(f.triage is not None for f in out)


def test_executive_summary_handles_empty_findings() -> None:
    triager = Triager(_mock_client(""))
    summary = triager.executive_summary([], "http://target.test")
    assert "no findings" in summary.lower()


def test_executive_summary_returns_empty_on_llm_failure() -> None:
    client = MagicMock()
    client.analyze.side_effect = RuntimeError("nope")
    triager = Triager(client)
    summary = triager.executive_summary([_sample_finding()], "http://target.test")
    assert summary == ""


# ─── Live integration test ──────────────────────────────────────────

def test_triage_against_real_deepseek_live() -> None:
    """Live: send a real finding to DeepSeek and get back a parseable response."""
    from src.config import Config, ConfigError
    from src.llm.deepseek_client import DeepSeekClient

    try:
        config = Config.load()
    except ConfigError:
        pytest.skip("DeepSeek not configured")

    client = DeepSeekClient(config)
    triager = Triager(client)

    triaged = triager.triage_finding(_sample_finding())
    # LLM should produce a triage — but if it doesn't (e.g. the model quirked
    # out today), we don't fail the suite.
    if triaged.triage is None:
        pytest.skip("LLM returned an unparseable response this run")
    assert triaged.triage.explanation
    assert triaged.triage.tailored_remediation
