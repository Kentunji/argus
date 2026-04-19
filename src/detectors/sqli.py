"""SQL Injection detector for Argus.

Three complementary techniques:

1. Error-based: inject syntax-breaking characters and look for database
   error messages in the response.

2. Status-change: compare HTTP status code between a syntax-breaking payload
   and a tautology payload. A 500-vs-200 swing is strong evidence the input
   reaches a SQL parser.

3. Boolean-based: TRUE vs FALSE tautology payloads, comparing response
   bodies. Catches injections where status doesn't change.

The detector probes both form-encoded AND JSON payloads. Modern APIs only
accept JSON, so form-only detection misses real vulnerabilities.

Time-based detection is deferred to v0.2.

Payloads are inert: they don't drop tables, exfiltrate data, or alter state.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import requests

from src.crawler import CrawlResult, Form
from src.detectors.base import Detector
from src.findings import Confidence, Evidence, Finding, Severity
from src.http_client import fetch
from src.logger import get_logger

log = get_logger(__name__)

_ERROR_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("SQLite", re.compile(r"SQLITE_ERROR|sqlite3\.|near\s+\".*?\":\s+syntax error", re.IGNORECASE)),
    ("MySQL", re.compile(r"you have an error in your sql syntax|warning:\s*mysql|mysql_fetch", re.IGNORECASE)),
    ("PostgreSQL", re.compile(r"pg_query\(\)|psql:|PostgreSQL.*?ERROR|unterminated quoted string", re.IGNORECASE)),
    ("MSSQL", re.compile(r"unclosed quotation mark|Microsoft OLE DB|SQL Server.*?Error", re.IGNORECASE)),
    ("Oracle", re.compile(r"ORA-\d{5}|Oracle.*?Driver", re.IGNORECASE)),
    ("Generic", re.compile(r"sql syntax|sqlexception|syntax error.*?query", re.IGNORECASE)),
]

_SKIP_INPUT_TYPES = {"checkbox", "radio", "file", "submit", "button", "image", "reset", "color", "range"}

_ERROR_PAYLOAD = "'"
_TRUE_PAYLOAD = "' OR '1'='1"
_FALSE_PAYLOAD = "' AND '1'='2"
_BYPASS_PAYLOAD = "' OR 1=1--"


def _detect_db_error(html: str) -> tuple[bool, str]:
    for db, pattern in _ERROR_PATTERNS:
        if pattern.search(html):
            return True, db
    return False, ""


def _inject_into_url(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    qs = dict(parse_qsl(parsed.query, keep_blank_values=True))
    qs[param] = value
    return urlunparse(parsed._replace(query=urlencode(qs)))


def _significant_diff(a: str, b: str) -> bool:
    if abs(len(a) - len(b)) > 200:
        return True
    a_first = a.splitlines()[0] if a else ""
    b_first = b.splitlines()[0] if b else ""
    return a_first != b_first


class SQLiDetector(Detector):
    name = "sqli"

    def run(self, crawl: CrawlResult, session: requests.Session) -> list[Finding]:
        findings: list[Finding] = []
        counter = 0

        for url in crawl.urls_visited:
            parsed = urlparse(url)
            for param in dict(parse_qsl(parsed.query, keep_blank_values=True)):
                finding = self._probe_url_param(url, param, session)
                if finding:
                    counter += 1
                    findings.append(self._with_id(finding, counter))

        for form in crawl.forms:
            for inp in form.inputs:
                if inp.type.lower() in _SKIP_INPUT_TYPES:
                    continue
                finding = self._probe_form_input(form, inp.name, session)
                if finding:
                    counter += 1
                    findings.append(self._with_id(finding, counter))

        return findings

    def _with_id(self, finding: Finding, n: int) -> Finding:
        return Finding(
            id=f"ARG-SQLI-{n:03d}",
            detector=finding.detector,
            type=finding.type,
            severity=finding.severity,
            confidence=finding.confidence,
            cwe=finding.cwe,
            owasp=finding.owasp,
            evidence=finding.evidence,
            remediation=finding.remediation,
        )

    # ─── URL params ─────────────────────────────────────────────────

    def _probe_url_param(self, url: str, param: str, session: requests.Session) -> Finding | None:
        try:
            probe_url = _inject_into_url(url, param, _ERROR_PAYLOAD)
            resp = fetch(session, probe_url)
        except requests.RequestException:
            return None

        found, db = _detect_db_error(resp.text)
        if found:
            return self._build_finding(
                method="GET", probe_url=probe_url, parameter=param, payload=_ERROR_PAYLOAD,
                indicator=f"{db} error message leaked in response", response=resp.text,
                confidence=Confidence.CONFIRMED, type_label="SQL Injection (error-based)",
            )

        try:
            t_url = _inject_into_url(url, param, _TRUE_PAYLOAD)
            f_url = _inject_into_url(url, param, _FALSE_PAYLOAD)
            t_resp = fetch(session, t_url)
            f_resp = fetch(session, f_url)
        except requests.RequestException:
            return None

        if _significant_diff(t_resp.text, f_resp.text):
            return self._build_finding(
                method="GET", probe_url=t_url, parameter=param,
                payload=f"{_TRUE_PAYLOAD} vs {_FALSE_PAYLOAD}",
                indicator="Boolean-based: TRUE and FALSE payloads produced significantly different responses",
                response=t_resp.text, confidence=Confidence.LIKELY,
                type_label="SQL Injection (boolean-based)",
            )
        return None

    # ─── Form inputs ────────────────────────────────────────────────

    def _probe_form_input(self, form: Form, param: str, session: requests.Session) -> Finding | None:
        finding = self._probe_form_encoded(form, param, session)
        if finding:
            return finding
        return self._probe_json(form, param, session)

    def _probe_form_encoded(self, form: Form, param: str, session: requests.Session) -> Finding | None:
        body = self._send_form(form, param, _ERROR_PAYLOAD, session)
        if body is not None:
            found, db = _detect_db_error(body)
            if found:
                return self._build_finding(
                    method=form.method, probe_url=form.action, parameter=param,
                    payload=_ERROR_PAYLOAD, indicator=f"{db} error message leaked in response",
                    response=body, confidence=Confidence.CONFIRMED,
                    type_label="SQL Injection (error-based)",
                )

        t_body = self._send_form(form, param, _TRUE_PAYLOAD, session)
        f_body = self._send_form(form, param, _FALSE_PAYLOAD, session)
        if t_body is not None and f_body is not None and _significant_diff(t_body, f_body):
            return self._build_finding(
                method=form.method, probe_url=form.action, parameter=param,
                payload=f"{_TRUE_PAYLOAD} vs {_FALSE_PAYLOAD}",
                indicator="Boolean-based: TRUE and FALSE payloads produced significantly different responses",
                response=t_body, confidence=Confidence.LIKELY,
                type_label="SQL Injection (boolean-based)",
            )
        return None

    def _send_form(self, form: Form, param: str, payload: str, session: requests.Session) -> str | None:
        try:
            data = {i.name: (payload if i.name == param else (i.value or "test")) for i in form.inputs}
            if form.method == "POST":
                resp = fetch(session, form.action, method="POST", data=data)
            else:
                probe_url = form.action + ("&" if "?" in form.action else "?") + urlencode(data)
                resp = fetch(session, probe_url)
            return resp.text
        except requests.RequestException as exc:
            log.warning("Form probe failed on %s: %s", form.action, exc)
            return None

    def _probe_json(self, form: Form, param: str, session: requests.Session) -> Finding | None:
        """Probe form action as JSON. Catches modern API endpoints."""
        def build(inject_value: str) -> dict:
            return {i.name: (inject_value if i.name == param else (i.value or "test")) for i in form.inputs}

        try:
            broken_resp = fetch(session, form.action, method="POST", json=build(_ERROR_PAYLOAD))
            bypass_resp = fetch(session, form.action, method="POST", json=build(_BYPASS_PAYLOAD))
        except requests.RequestException as exc:
            log.warning("JSON probe failed on %s: %s", form.action, exc)
            return None

        # Signal A: SQL error message in either response
        for resp, payload, label in [(broken_resp, _ERROR_PAYLOAD, "broken"), (bypass_resp, _BYPASS_PAYLOAD, "bypass")]:
            found, db = _detect_db_error(resp.text)
            if found:
                return self._build_finding(
                    method="POST (JSON)", probe_url=form.action, parameter=param,
                    payload=payload, indicator=f"{db} error message leaked in JSON response",
                    response=resp.text, confidence=Confidence.CONFIRMED,
                    type_label="SQL Injection (error-based, JSON)",
                )

        # Signal B: status-code swing
        if broken_resp.status_code >= 400 and 200 <= bypass_resp.status_code < 300:
            return self._build_finding(
                method="POST (JSON)", probe_url=form.action, parameter=param,
                payload=f"{_ERROR_PAYLOAD} ({broken_resp.status_code}) vs {_BYPASS_PAYLOAD} ({bypass_resp.status_code})",
                indicator=(
                    f"Status code swing: broken payload returned {broken_resp.status_code}, "
                    f"tautology payload returned {bypass_resp.status_code} — input reaches SQL parser"
                ),
                response=bypass_resp.text, confidence=Confidence.CONFIRMED,
                type_label="SQL Injection (auth bypass / status-change)",
            )

        return None

    # ─── Finding factory ────────────────────────────────────────────

    def _build_finding(
        self, *, method: str, probe_url: str, parameter: str, payload: str,
        indicator: str, response: str, confidence: Confidence, type_label: str,
    ) -> Finding:
        snippet = response[:300] if len(response) <= 300 else response[:300] + "..."
        evidence = Evidence(
            method=method, url=probe_url, parameter=parameter, payload=payload,
            indicator=indicator, response_snippet=snippet,
        )
        return Finding(
            id="", detector=self.name, type=type_label,
            severity=Severity.HIGH, confidence=confidence,
            cwe="CWE-89", owasp="A03:2021 Injection",
            evidence=evidence,
            remediation=(
                "Use parameterized queries (prepared statements) for every SQL "
                "operation. Never concatenate user input into SQL strings. ORMs "
                "with bind variables are a strong default. Validate input types "
                "and lengths server-side."
            ),
        )
