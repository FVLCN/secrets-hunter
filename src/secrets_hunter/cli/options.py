import argparse

from secrets_hunter.config import (
    DEFAULT_FINDING_OUTPUT_OPTIONS,
    DEFAULT_SCAN_OPTIONS
)

from .defaults import DEFAULT_FAIL_ON_FINDINGS, DEFAULT_LOG_LEVEL


def add_config_option(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--config",
        action="append",
        default=None,
        metavar="FILE",
        help="path to TOML overlay config. Can be used multiple times.",
    )


def add_scan_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--reveal-findings",
        action="store_true",
        default=DEFAULT_FINDING_OUTPUT_OPTIONS.reveal_findings,
        help=(
            "reveal findings in output "
            f"(default: {DEFAULT_FINDING_OUTPUT_OPTIONS.reveal_findings})"
        )
    )
    add_config_option(parser)
    parser.add_argument(
        "--json",
        dest="json_output",
        metavar="FILE",
        help="export results to JSON file",
    )
    parser.add_argument(
        "--sarif",
        dest="sarif_output",
        metavar="FILE",
        help="export results to SARIF file",
    )
    parser.add_argument(
        "--hex-entropy",
        type=float,
        default=DEFAULT_SCAN_OPTIONS.hex_entropy_threshold,
        help=(
            "hex entropy threshold "
            f"(default: {DEFAULT_SCAN_OPTIONS.hex_entropy_threshold})"
        )
    )
    parser.add_argument(
        "--b64-entropy",
        type=float,
        default=DEFAULT_SCAN_OPTIONS.b64_entropy_threshold,
        help=(
            "base64 entropy threshold "
            f"(default: {DEFAULT_SCAN_OPTIONS.b64_entropy_threshold})"
        )
    )
    parser.add_argument(
        "--min-length",
        type=int,
        default=DEFAULT_SCAN_OPTIONS.min_string_length,
        help=(
            "minimum string length "
            f"(default: {DEFAULT_SCAN_OPTIONS.min_string_length})"
        )
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_SCAN_OPTIONS.max_workers,
        help=(
            "number of parallel workers "
            f"(default: {DEFAULT_SCAN_OPTIONS.max_workers})"
        )
    )
    parser.add_argument(
        "--max-source-bytes",
        type=int,
        default=DEFAULT_SCAN_OPTIONS.max_source_bytes,
        help=(
            "maximum in-memory source or Git output size in bytes "
            f"(default: {DEFAULT_SCAN_OPTIONS.max_source_bytes})"
        )
    )
    parser.add_argument(
        "--source-timeout",
        type=float,
        default=DEFAULT_SCAN_OPTIONS.source_timeout_seconds,
        help=(
            "source I/O timeout in seconds "
            f"(default: {DEFAULT_SCAN_OPTIONS.source_timeout_seconds})"
        )
    )
    parser.add_argument(
        "--log-level",
        type=str,
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default=DEFAULT_LOG_LEVEL,
        help=f"log level (default: {DEFAULT_LOG_LEVEL})",
    )
    parser.add_argument(
        "--min-confidence",
        type=int,
        default=DEFAULT_FINDING_OUTPUT_OPTIONS.min_confidence,
        help=(
            "minimum confidence of findings to display "
            f"(default: {DEFAULT_FINDING_OUTPUT_OPTIONS.min_confidence})"
        ),
    )
    parser.add_argument(
        "--fail-on-findings",
        action="store_true",
        default=DEFAULT_FAIL_ON_FINDINGS,
        help="exit with code 2 if report contains non-rejected findings",
    )
    parser.add_argument(
        "--truncate-long-matches",
        action="store_true",
        dest="truncate_long_matches",
        default=DEFAULT_FINDING_OUTPUT_OPTIONS.truncate_long_matches,
        help="truncate long finding matches in output",
    )
