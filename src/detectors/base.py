"""Abstract base for all Argus detectors.

A detector takes a CrawlResult plus an HTTP session and returns Findings.
Every detector — XSS, SQLi, headers, future ones — conforms to this shape so
the scan loop and reporter never need to know the details.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

import requests

from src.crawler import CrawlResult
from src.findings import Finding


class Detector(ABC):
    """Base class for vulnerability detectors."""

    name: str = "base"  # subclasses override

    @abstractmethod
    def run(self, crawl: CrawlResult, session: requests.Session) -> list[Finding]:
        """Inspect the crawl result and return any findings."""
        raise NotImplementedError
