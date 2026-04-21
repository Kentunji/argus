"""Abstract reporter interface."""

from __future__ import annotations

from abc import ABC, abstractmethod

from src.scan_result import ScanResult


class Reporter(ABC):
    """Subclasses turn a ScanResult into output (terminal, file, etc.)."""

    @abstractmethod
    def render(self, result: ScanResult) -> str | None:
        """Produce the report. Return a path/string for file outputs, None for stdout."""
        raise NotImplementedError

