"""Tests for the CLI parser and dispatcher."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.cli import VERSION, _build_parser, main


def test_version_command(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["version"])
    captured = capsys.readouterr()
    assert rc == 0
    assert VERSION in captured.out


def test_no_command_prints_help(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main([])
    captured = capsys.readouterr()
    assert rc == 1
    assert "Argus" in captured.out


def test_scan_parses_basic_args() -> None:
    parser = _build_parser()
    args = parser.parse_args(["scan", "http://localhost:3000"])
    assert args.command == "scan"
    assert args.target == "http://localhost:3000"
    assert args.no_triage is False
    assert args.no_html is False
    assert args.no_json is False


def test_scan_parses_all_flags() -> None:
    parser = _build_parser()
    args = parser.parse_args([
        "scan", "http://target.test",
        "--no-triage", "--no-html", "--no-json",
        "--depth", "5", "--max-pages", "100",
        "--reports-dir", "out", "--log-level", "DEBUG",
    ])
    assert args.no_triage is True
    assert args.no_html is True
    assert args.no_json is True
    assert args.depth == 5
    assert args.max_pages == 100
    assert args.reports_dir == Path("out")
    assert args.log_level == "DEBUG"


def test_scan_invalid_log_level_rejected(capsys: pytest.CaptureFixture[str]) -> None:
    parser = _build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["scan", "http://x", "--log-level", "BANANA"])


def test_unknown_command_shows_help(capsys: pytest.CaptureFixture[str]) -> None:
    parser = _build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["unknown"])


def test_scan_handles_config_error_gracefully(capsys: pytest.CaptureFixture[str]) -> None:
    """Missing .env should produce a friendly error, not a crash."""
    from src.config import ConfigError

    with patch("src.cli.Config.load", side_effect=ConfigError("No DEEPSEEK_API_KEY")):
        rc = main(["scan", "http://localhost:3000"])

    captured = capsys.readouterr()
    assert rc == 2
    assert "Configuration error" in captured.err
    assert "DEEPSEEK_API_KEY" in captured.err


def test_scan_returns_1_on_high_severity_findings(tmp_path: Path) -> None:
    """Exit code 1 when HIGH/CRITICAL findings exist (CI integration story)."""
    from datetime import datetime, timezone
    from src.findings import Confidence, Evidence, Finding, Severity
    from src.scan_result import ScanResult

    fake_result = ScanResult(
        target="http://x",
        started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        completed_at=datetime(2026, 1, 1, 0, 0, 1, tzinfo=timezone.utc),
        findings=[
            Finding(
                id="ARG-X-001", detector="x", type="t",
                severity=Severity.HIGH, confidence=Confidence.LIKELY,
                cwe="CWE-89", owasp="A03",
                evidence=Evidence("GET", "u", "p", "y", "i", "s"),
                remediation="r",
            )
        ],
    )

    with (
        patch("src.cli.Config.load") as mock_config,
        patch("src.scanner.Scanner") as mock_scanner,
    ):
        cfg = MagicMock()
        cfg.reports_dir = tmp_path
        cfg.log_level = "INFO"
        cfg.max_crawl_depth = 3
        cfg.max_crawl_pages = 200
        mock_config.return_value = cfg

        scanner_instance = MagicMock()
        scanner_instance.scan.return_value = fake_result
        mock_scanner.return_value = scanner_instance

        rc = main(["scan", "http://x", "--no-html", "--no-json"])

    assert rc == 1


def test_scan_returns_0_on_no_high_findings(tmp_path: Path) -> None:
    """Exit code 0 when only LOW/INFO findings exist."""
    from datetime import datetime, timezone
    from src.findings import Confidence, Evidence, Finding, Severity
    from src.scan_result import ScanResult

    fake_result = ScanResult(
        target="http://x",
        started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        completed_at=datetime(2026, 1, 1, 0, 0, 1, tzinfo=timezone.utc),
        findings=[
            Finding(
                id="ARG-X-001", detector="x", type="t",
                severity=Severity.LOW, confidence=Confidence.LIKELY,
                cwe="CWE-200", owasp="A05",
                evidence=Evidence("GET", "u", "p", "y", "i", "s"),
                remediation="r",
            )
        ],
    )

    with (
        patch("src.cli.Config.load") as mock_config,
        patch("src.scanner.Scanner") as mock_scanner,
    ):
        cfg = MagicMock()
        cfg.reports_dir = tmp_path
        cfg.log_level = "INFO"
        cfg.max_crawl_depth = 3
        cfg.max_crawl_pages = 200
        mock_config.return_value = cfg

        scanner_instance = MagicMock()
        scanner_instance.scan.return_value = fake_result
        mock_scanner.return_value = scanner_instance

        rc = main(["scan", "http://x", "--no-html", "--no-json"])

    assert rc == 0
