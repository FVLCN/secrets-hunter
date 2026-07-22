import argparse
import logging
import time

from secrets_hunter.application import ScanApplication
from secrets_hunter.application.source_validation import ScanSourceValidator
from secrets_hunter.cli.scan_progress import TerminalScanProgressObserver
from secrets_hunter.cli.scan_reporting import (
    log_findings_summary,
    log_scan_result
)
from secrets_hunter.cli.source_adapters import SCAN_SOURCE_ADAPTERS
from secrets_hunter.config import FindingOutputOptions, ScanOptions
from secrets_hunter.config.validation import (
    FindingOutputOptionsValidator,
    ScanOptionsValidator
)
from secrets_hunter.models import Disposition
from secrets_hunter.reporters.console_reporter import ConsoleReporter
from secrets_hunter.reporters.findings_output_processor import FindingsOutputProcessor
from secrets_hunter.reporters.json_reporter import JSONReporter
from secrets_hunter.reporters.sarif_reporter import SARIFReporter
from secrets_hunter.runtime import load_application_runtime

from ..options import add_scan_options
from ..protocols import SubparserRegistry
from ..validation import (
    validate_config_options,
    validate_output_options
)


NAME = "scan"


def register(subparsers: SubparserRegistry) -> None:
    parser = subparsers.add_parser(
        NAME,
        help="scan a source for secrets (default command)",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.set_defaults(
        command_handler=run,
        command_validator=validate
    )

    common_parser = argparse.ArgumentParser(add_help=False)
    add_scan_options(common_parser)
    source_subparsers = parser.add_subparsers(
        dest="scan_mode",
        required=True,
        help="available scan sources"
    )
    for adapter in SCAN_SOURCE_ADAPTERS:
        adapter.register(source_subparsers, common_parser)


def validate(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    validate_config_options(parser, args)

    try:
        ScanOptionsValidator.validate(create_scan_options(args))
        FindingOutputOptionsValidator.validate(
            create_finding_output_options(args)
        )
        ScanSourceValidator.validate(args.source_factory(args))
    except (TypeError, ValueError) as error:
        parser.error(str(error))

    validate_output_options(parser, args)


def create_scan_options(args: argparse.Namespace) -> ScanOptions:
    return ScanOptions(
        hex_entropy_threshold=args.hex_entropy,
        b64_entropy_threshold=args.b64_entropy,
        min_string_length=args.min_length,
        max_workers=args.workers,
        max_source_bytes=args.max_source_bytes,
        source_timeout_seconds=args.source_timeout
    )


def create_finding_output_options(
    args: argparse.Namespace
) -> FindingOutputOptions:
    return FindingOutputOptions(
        min_confidence=args.min_confidence,
        reveal_findings=args.reveal_findings,
        truncate_long_matches=args.truncate_long_matches
    )


def run(args: argparse.Namespace) -> int:
    scan_options = create_scan_options(args)
    output_options = create_finding_output_options(args)
    runtime = load_application_runtime(args.config)

    logging.basicConfig(
        level=args.log_level,
        format="%(asctime)s | %(levelname)s | %(module)s.%(funcName)s:%(lineno)d - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    progress_observer = TerminalScanProgressObserver()
    source = args.source_factory(args)
    application = ScanApplication(runtime, scan_options)
    started = time.monotonic()
    try:
        result = application.scan(
            source,
            progress_observer=progress_observer
        )
    finally:
        progress_observer.finish_progress_line()

    log_scan_result(result, time.monotonic() - started)

    if result.aborted:
        return 1

    findings = FindingsOutputProcessor.prepare(
        list(result.findings),
        output_options
    )

    if result.complete or findings:
        log_findings_summary(findings, output_options)

    if args.json_output:
        JSONReporter.export(findings, args.json_output)
    elif args.sarif_output:
        SARIFReporter.export(findings, args.sarif_output)
    else:
        ConsoleReporter.format_report(findings)

    if not result.complete:
        return 1

    if args.fail_on_findings and any(
        finding.disposition is not Disposition.SUPPRESS for finding in findings
    ):
        return 2

    return 0
