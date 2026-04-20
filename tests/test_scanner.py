"""End-to-end tests for the Scanner orchestrator."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
import requests

from src.config import Config
from src.scanner import Scanner


def _config(tmp_path: Path, seed_path: Path | None = None) -> Config:
    return Config(
        deepseek_api_key="test-key",
        deepseek_base_url="https://api.deepseek.com",
        deepseek_model="deepseek-chat",
        target_url="http://localhost:3000",
        max_crawl_depth=1,
        max_crawl_pages=10,
        scan_timeout=30,
        log_level="INFO",
        seed_forms_path=seed_path,
        reports_dir=tmp_path,
    )


def test_scanner_against_juice_shop_live(tmp_path: Path) -> None:
    """Live: scan Juice Shop end-to-end with seed forms.

    Asserts: scan completes, JSON written, ≥1 finding (headers always trigger).
    """
    try:
        requests.get("http://localhost:3000", timeout=3)
    except requests.RequestException:
        pytest.skip("Juice Shop not reachable on localhost:3000 (SSH tunnel down?)")

    # Synthesize a seed forms file pointing at Juice Shop's login
    seed_path = tmp_path / "seed.yml"
    seed_path.write_text(
        """
forms:
  - action: http://localhost:3000/rest/user/login
    method: POST
    inputs:
      - name: email
        type: email
      - name: password
        type: password
"""
    )

    config = _config(tmp_path, seed_path)
    scanner = Scanner(config)
    result, json_path, html_path = scanner.scan_and_report("http://localhost:3000")

    # Headers detector always finds something on Juice Shop
    assert len(result.findings) >= 1
    # Seed forms loaded
    assert result.forms_tested >= 1
    # All three detectors ran
    assert "xss" in result.detectors_run
    assert "sqli" in result.detectors_run
    assert "headers" in result.detectors_run
    # JSON report on disk
    assert Path(json_path).exists()
    assert Path(json_path).exists()
    assert Path(html_path).exists()
    # SQLi detector finds the login bypass via seeded form
    sqli_findings = [f for f in result.findings if "SQL" in f.type]
    assert len(sqli_findings) >= 1, "Expected SQLi finding via seed forms"


def test_scanner_handles_unreachable_target(tmp_path: Path) -> None:
    """Scanner shouldn't crash when the target is dead."""
    config = _config(tmp_path)
    scanner = Scanner(config)
    result = scanner.scan("http://localhost:1")  # nothing listening on port 1

    # Scan completes with a result, even if everything errored
    assert result.completed_at is not None
    # Shouldn't have crashed; may have errors recorded
    assert isinstance(result.errors, list)
