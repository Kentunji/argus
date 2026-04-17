"""Central logger for Argus.

All modules should call `get_logger(__name__)` instead of using `print`. This
gives us consistent formatting, log levels, and a single place to change how
logs render (e.g. adding a file sink later).
"""

from __future__ import annotations

import logging

from rich.logging import RichHandler

_CONFIGURED = False


def configure_logging(level: str = "INFO") -> None:
    """Configure root logging once. Idempotent — safe to call multiple times."""
    global _CONFIGURED
    if _CONFIGURED:
        return

    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True, show_path=False)],
    )
    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    """Return a named logger. Call `configure_logging` at app start."""
    return logging.getLogger(name)
