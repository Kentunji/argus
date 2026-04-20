"""Command-line interface for Argus.

Usage:
    argus scan <url> [options]
    argus version
    argus --help

Examples:
    argus scan http://localhost:3000
    argus scan http://localhost:3000 --no-triage --no-html
    argus scan https://example.com --depth 2 --max-pages 50
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from src.config import Config, ConfigError
from src.logger import configure_logging, get_logger

VERSION = "0.1.0"

log = get_logger(__name__)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="argus",
        description=(
            "Argus — AI-powered web application vulnerability scanner. "
            "Crawls a target, probes for XSS/SQLi/header misconfigurations, "
            "and uses an LLM to triage findings and generate remediation."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  argus scan http://localhost:3000\n"
            "  argus scan https://example.com --no-triage\n"
            "  argus scan http://localhost:3000 --depth 2 --no-html\n"
            "  argus version\n"
            "\n"
            "Authorized testing only. Do not use against systems you do not "
            "own or have explicit written permission to test."
        ),
    )

    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    # ── scan ──
    scan = sub.add_parser(
        "scan",
        help="Run a scan against a target URL",
        description="Run a vulnerability scan against the given target URL.",
    )
    scan.add_argument(
        "target",
        help="Target URL to scan (e.g. http://localhost:3000)",
    )
    scan.add_argument(
        "--no-triage",
        action="store_true",
        help="Skip LLM triage (faster scans, no DeepSeek API calls)",
    )
    scan.add_argument(
        "--no-html",
        action="store_true",
        help="Skip HTML report (terminal + JSON only)",
    )
    scan.add_argument(
        "--no-json",
        action="store_true",
        help="Skip JSON report (terminal only)",
    )
    scan.add_argument(
        "--depth",
        type=int,
        metavar="N",
        help="Override MAX_CRAWL_DEPTH from .env",
    )
    scan.add_argument(
        "--max-pages",
        type=int,
        metavar="N",
        help="Override MAX_CRAWL_PAGES from .env",
    )
    scan.add_argument(
        "--reports-dir",
        type=Path,
        metavar="PATH",
        help="Override REPORTS_DIR from .env",
    )
    scan.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Override LOG_LEVEL from .env",
    )

    # ── version ──
    sub.add_parser("version", help="Print Argus version and exit")

    return parser


def _apply_overrides(config: Config, args: argparse.Namespace) -> Config:
    """Return a new Config with CLI overrides applied. Config is frozen so we replace."""
    from dataclasses import replace
    overrides: dict = {}
    if args.depth is not None:
        overrides["max_crawl_depth"] = args.depth
    if args.max_pages is not None:
        overrides["max_crawl_pages"] = args.max_pages
    if args.reports_dir is not None:
        rd = args.reports_dir if args.reports_dir.is_absolute() else Path.cwd() / args.reports_dir
        overrides["reports_dir"] = rd
    if args.log_level is not None:
        overrides["log_level"] = args.log_level
    return replace(config, **overrides) if overrides else config


def _cmd_scan(args: argparse.Namespace) -> int:
    # Local import so 'version' command doesn't pull in heavy deps.
    from src.reporters.html_writer import HtmlReporter
    from src.reporters.json_writer import JsonReporter
    from src.reporters.terminal import TerminalReporter
    from src.scanner import Scanner

    try:
        config = Config.load()
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        print("\nCopy .env.example to .env and fill in the required values.", file=sys.stderr)
        return 2

    config = _apply_overrides(config, args)
    configure_logging(config.log_level)

    scanner = Scanner(config, enable_triage=not args.no_triage)
    result = scanner.scan(args.target)

    # Always render terminal output
    TerminalReporter().render(result)

    # Optional report files
    if not args.no_json:
        json_path = JsonReporter(config.reports_dir).render(result)
        log.info("JSON report: %s", json_path)
    if not args.no_html:
        html_path = HtmlReporter(config.reports_dir).render(result)
        log.info("HTML report: %s", html_path)

    # Exit code: 0 if nothing critical/high, 1 if HIGH+ findings exist.
    # Useful for CI pipelines: `argus scan ... && deploy` only deploys if clean.
    high_or_critical = sum(
        1 for f in result.findings
        if f.severity.value in ("HIGH", "CRITICAL")
    )
    return 1 if high_or_critical > 0 else 0


def _cmd_version(_args: argparse.Namespace) -> int:
    print(f"Argus {VERSION}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 1

    if args.command == "scan":
        return _cmd_scan(args)
    if args.command == "version":
        return _cmd_version(args)

    parser.print_help()
    return 1
