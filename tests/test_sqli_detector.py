"""Tests for the SQL Injection detector."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
import requests

from src.crawler import CrawlResult, Form, FormInput
from src.detectors.sqli import (
    SQLiDetector,
    _detect_db_error,
    _significant_diff,
)
from src.findings import Confidence


# ─── Error-pattern unit tests ───────────────────────────────────────

def test_detect_db_error_matches_sqlite() -> None:
    body = 'SQLITE_ERROR: near "\'": syntax error'
    found, db = _detect_db_error(body)
    assert found
    assert db == "SQLite"


def test_detect_db_error_matches_mysql() -> None:
    body = "You have an error in your SQL syntax near '1'"
    found, db = _detect_db_error(body)
    assert found
    assert db == "MySQL"


def test_detect_db_error_no_false_positive_on_clean_response() -> None:
    body = "<html><body>Welcome to the app.</body></html>"
    found, _ = _detect_db_error(body)
    assert not found


# ─── Diff helper ────────────────────────────────────────────────────

def test_significant_diff_detects_large_size_change() -> None:
    a = "x" * 1000
    b = "x" * 100
    assert _significant_diff(a, b)


def test_significant_diff_ignores_minor_changes() -> None:
    a = "<html>same content</html>"
    b = "<html>same content</html>"
    assert not _significant_diff(a, b)


# ─── Detector-level tests with a SQL-buggy mock app ─────────────────

def _mock_session(behavior: dict[str, str], default_status: int = 200) -> MagicMock:
    """Mock app whose response depends on the injected payload.

    `behavior` maps payload-substring to canned response body.
    Accepts both form-encoded (`data=`) and JSON (`json=`) requests.
    """
    session = MagicMock(spec=requests.Session)

    def _request(method, url, data=None, json=None, timeout=None, allow_redirects=True):
        # Find the payload — in URL query, form data, or JSON body
        sent_value = ""
        if json:
            sent_value = next(iter(json.values())) if json else ""
        elif data:
            sent_value = next(iter(data.values()))
        else:
            from urllib.parse import parse_qsl, urlparse
            qs = dict(parse_qsl(urlparse(url).query, keep_blank_values=True))
            sent_value = next(iter(qs.values())) if qs else ""

        body = "<html>default</html>"
        status = default_status
        for needle, response in behavior.items():
            if needle in str(sent_value):
                body = response
                break

        resp = MagicMock()
        resp.url = url
        resp.status_code = status
        resp.headers = {"Content-Type": "text/html"}
        resp.text = body
        resp.elapsed.total_seconds.return_value = 0.01
        return resp

    session.request.side_effect = _request
    return session


def test_sqli_detector_finds_error_based() -> None:
    crawl_result = CrawlResult(target="http://target.test")
    crawl_result.forms.append(
        Form(
            action="http://target.test/login",
            method="POST",
            inputs=(FormInput(name="email", type="email"),),
            source_page="http://target.test/",
        )
    )
    session = _mock_session({"'": 'SQLITE_ERROR: near "\'": syntax error'})

    findings = SQLiDetector().run(crawl_result, session)
    assert len(findings) >= 1
    assert findings[0].confidence == Confidence.CONFIRMED
    assert "error-based" in findings[0].type
    assert findings[0].id == "ARG-SQLI-001"
    assert findings[0].cwe == "CWE-89"


def test_sqli_detector_finds_boolean_based() -> None:
    crawl_result = CrawlResult(target="http://target.test")
    crawl_result.forms.append(
        Form(
            action="http://target.test/products",
            method="GET",
            inputs=(FormInput(name="id", type="text"),),
            source_page="http://target.test/",
        )
    )
    session = _mock_session(
        {
            "'1'='1": "<html>" + ("product " * 200) + "</html>",
            "'1'='2": "<html>no results</html>",
        }
    )

    findings = SQLiDetector().run(crawl_result, session)
    assert len(findings) >= 1
    assert findings[0].confidence == Confidence.LIKELY
    assert "boolean-based" in findings[0].type


def test_sqli_detector_no_false_positive() -> None:
    crawl_result = CrawlResult(target="http://target.test")
    crawl_result.forms.append(
        Form(
            action="http://target.test/safe",
            method="POST",
            inputs=(FormInput(name="q", type="text"),),
            source_page="http://target.test/",
        )
    )
    # Same response (and same status) regardless of payload — properly parameterized.
    session = _mock_session({})

    findings = SQLiDetector().run(crawl_result, session)
    assert findings == []


def test_sqli_detector_skips_non_text_inputs() -> None:
    crawl_result = CrawlResult(target="http://target.test")
    crawl_result.forms.append(
        Form(
            action="http://target.test/form",
            method="POST",
            inputs=(
                FormInput(name="agree", type="checkbox"),
                FormInput(name="file", type="file"),
            ),
            source_page="http://target.test/",
        )
    )
    session = _mock_session({"'": "SQLITE_ERROR"})

    findings = SQLiDetector().run(crawl_result, session)
    assert findings == []


# ─── Live integration test against Juice Shop ───────────────────────

def test_sqli_detector_against_juice_shop_login_live() -> None:
    """Live: probe Juice Shop's login form, which is famously SQLi-vulnerable."""
    try:
        requests.get("http://localhost:3000", timeout=3)
    except requests.RequestException:
        pytest.skip("Juice Shop not reachable on localhost:3000 (SSH tunnel down?)")

    from src.http_client import build_session
    session = build_session()

    crawl_result = CrawlResult(target="http://localhost:3000")
    crawl_result.forms.append(
        Form(
            action="http://localhost:3000/rest/user/login",
            method="POST",
            inputs=(
                FormInput(name="email", type="email"),
                FormInput(name="password", type="password"),
            ),
            source_page="http://localhost:3000/",
        )
    )

    findings = SQLiDetector().run(crawl_result, session)
    assert any("SQL Injection" in f.type for f in findings), (
        f"Expected SQLi finding on Juice Shop login. Got: {[f.type for f in findings]}"
    )
