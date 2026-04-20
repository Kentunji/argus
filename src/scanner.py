"""Argus scan orchestrator."""

from __future__ import annotations

from src.config import Config
from src.crawler import CrawlResult, crawl
from src.detectors.headers import HeadersDetector
from src.detectors.sqli import SQLiDetector
from src.detectors.xss import XSSDetector
from src.http_client import build_session
from src.llm.deepseek_client import DeepSeekClient
from src.llm.triage import Triager
from src.logger import get_logger
from src.reporters.json_writer import JsonReporter
from src.reporters.terminal import TerminalReporter
from src.scan_result import ScanResult, now_utc
from src.seed_forms import load_seed_forms

log = get_logger(__name__)


class Scanner:
    def __init__(self, config: Config, *, enable_triage: bool = True) -> None:
        self._config = config
        self._detectors = [XSSDetector(), SQLiDetector(), HeadersDetector()]
        self._enable_triage = enable_triage
        self._triager: Triager | None = None
        if enable_triage:
            try:
                self._triager = Triager(DeepSeekClient(config))
            except Exception as exc:  # noqa: BLE001
                log.warning("LLM triage disabled — client init failed: %s", exc)

    def scan(self, target: str) -> ScanResult:
        result = ScanResult(target=target, started_at=now_utc())
        session = build_session()

        # Crawl
        log.info("Crawling %s (depth=%d, max=%d)",
                 target, self._config.max_crawl_depth, self._config.max_crawl_pages)
        try:
            crawl_result = crawl(
                target,
                max_depth=self._config.max_crawl_depth,
                max_pages=self._config.max_crawl_pages,
                session=session,
            )
        except Exception as exc:
            log.exception("Crawl failed")
            result.errors.append(f"crawl: {exc}")
            crawl_result = CrawlResult(target=target)

        result.urls_visited = len(crawl_result.urls_visited)

        # Merge seed forms
        try:
            seeded = load_seed_forms(self._config.seed_forms_path)
            crawl_result.forms.extend(seeded)
        except Exception as exc:
            log.exception("Seed forms load failed")
            result.errors.append(f"seed_forms: {exc}")

        result.forms_tested = len(crawl_result.forms)
        log.info("Discovered %d URL(s) and %d form(s)",
                 result.urls_visited, result.forms_tested)

        # Run detectors
        for detector in self._detectors:
            log.info("Running %s detector", detector.name)
            try:
                findings = detector.run(crawl_result, session)
                result.findings.extend(findings)
                result.detectors_run.append(detector.name)
                log.info("  %s found %d finding(s)", detector.name, len(findings))
            except Exception as exc:
                log.exception("Detector %s failed", detector.name)
                result.errors.append(f"detector:{detector.name}: {exc}")

        # LLM triage (optional, fails gracefully)
        if self._triager and result.findings:
            log.info("Running LLM triage on %d finding(s)", len(result.findings))
            result.findings = self._triager.triage_all(result.findings)
            result.executive_summary = self._triager.executive_summary(result.findings, target)

        result.completed_at = now_utc()
        return result

    def scan_and_report(self, target: str) -> tuple[ScanResult, str]:
        result = self.scan(target)
        TerminalReporter().render(result)
        json_path = JsonReporter(self._config.reports_dir).render(result)
        log.info("JSON report written to %s", json_path)
        return result, json_path
