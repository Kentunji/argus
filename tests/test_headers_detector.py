"""Tests for the security-headers + cookie-flags detector."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
import requests

from src.crawler import CrawlResult
from src.detectors.headers import HeadersDetector, _parse_cookie_flags
from src.findings import Severity


# ─── Cookie parsing ─────────────────────────────────────────────────

def test_parse_cookie_flags_detects_secure_httponly_samesite() -> None:
    raw = "session=abc123; Secure; HttpOnly; SameSite=Lax"
    cookies = _parse_cookie_flags(raw)
    assert "session" in cookies
    assert cookies["session"]["secure"] is True
    assert cookies["session"]["httponly"] is True
    assert cookies["session"]["samesite"].lower() == "lax"


def test_parse_cookie_flags_detects_missing_flags() -> None:
    raw = "session=abc123"
    cookies = _parse_cookie_flags(raw)
    assert cookies["session"]["secure"] is False
    assert cookies["session"]["httponly"] is False
    assert cookies["session"]["samesite"] == ""


# ─── Detector mock helper ───────────────────────────────────────────

def _mock_session(headers: dict[str, str]) -> MagicMock:
    session = MagicMock(spec=requests.Session)
    resp = MagicMock()
    resp.url = "http://target.test/"
    resp.status_code = 200
    resp.headers = headers
    resp.text = ""
    resp.elapsed.total_seconds.return_value = 0.01
    session.request.return_value = resp
    return session


def test_headers_detector_flags_all_missing_on_naked_response() -> None:
    crawl = CrawlResult(target="http://target.test/")
    session = _mock_session({})  # no security headers, no cookies

    findings = HeadersDetector().run(crawl, session)
    types = [f.type for f in findings]
    # HSTS skipped because target is HTTP, not HTTPS.
    # We expect: CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
    assert any("Content-Security-Policy" in t for t in types)
    assert any("X-Frame-Options" in t for t in types)
    assert any("X-Content-Type-Options" in t for t in types)


def test_headers_detector_includes_hsts_only_for_https() -> None:
    crawl_https = CrawlResult(target="https://target.test/")
    findings_https = HeadersDetector().run(crawl_https, _mock_session({}))
    assert any("Strict-Transport-Security" in f.type for f in findings_https)

    crawl_http = CrawlResult(target="http://target.test/")
    findings_http = HeadersDetector().run(crawl_http, _mock_session({}))
    assert not any("Strict-Transport-Security" in f.type for f in findings_http)


def test_headers_detector_skips_present_headers() -> None:
    crawl = CrawlResult(target="http://target.test/")
    session = _mock_session(
        {
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin",
            "Permissions-Policy": "camera=()",
        }
    )

    findings = HeadersDetector().run(crawl, session)
    # All checked headers present — no header findings (no cookies either)
    header_findings = [f for f in findings if f.type.startswith("Missing security header")]
    assert header_findings == []


def test_headers_detector_flags_insecure_cookie_flags() -> None:
    crawl = CrawlResult(target="https://target.test/")
    session = _mock_session(
        {
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin",
            "Permissions-Policy": "camera=()",
            "Strict-Transport-Security": "max-age=31536000",
            "Set-Cookie": "session=abc123",  # missing Secure, HttpOnly, SameSite
        }
    )

    findings = HeadersDetector().run(crawl, session)
    cookie_issues = [f.type for f in findings if "session" in f.type]
    assert any("Secure" in t for t in cookie_issues)
    assert any("HttpOnly" in t for t in cookie_issues)
    assert any("SameSite" in t for t in cookie_issues)


def test_headers_detector_no_findings_on_well_configured_site() -> None:
    crawl = CrawlResult(target="https://target.test/")
    session = _mock_session(
        {
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin",
            "Permissions-Policy": "camera=()",
            "Strict-Transport-Security": "max-age=31536000",
            "Set-Cookie": "session=abc; Secure; HttpOnly; SameSite=Lax",
        }
    )

    findings = HeadersDetector().run(crawl, session)
    assert findings == []


# ─── Live integration test ──────────────────────────────────────────

def test_headers_detector_against_juice_shop_live() -> None:
    """Live: Juice Shop is well-known to be missing several security headers."""
    try:
        requests.get("http://localhost:3000", timeout=3)
    except requests.RequestException:
        pytest.skip("Juice Shop not reachable on localhost:3000 (SSH tunnel down?)")

    from src.http_client import build_session
    crawl = CrawlResult(target="http://localhost:3000/")
    findings = HeadersDetector().run(crawl, build_session())

    # Juice Shop ships without CSP and without most hardening headers.
    # We expect at least one finding.
    assert len(findings) >= 1
    severities = {f.severity for f in findings}
    # Should be mostly INFO/LOW/MEDIUM, never HIGH for headers alone
    assert Severity.HIGH not in severities
