import argparse
import logging
import time

from secrets_hunter.application import ScanApplication
from secrets_hunter.cli.scan_progress import TerminalScanProgressObserver
from secrets_hunter.cli.scan_reporting import (
    log_findings_summary,
    log_scan_result
)
from secrets_hunter.cli.source_adapters import (
    CLI_SCAN_MODE_REGISTRY,
    SCAN_SOURCE_ADAPTERS
)
from secrets_hunter.config import (
    FindingPresentationOptions,
    FindingSelectionOptions,
    ScanOptions
)
from secrets_hunter.config.validation import (
    FindingPresentationOptionsValidator,
    FindingSelectionOptionsValidator,
    ScanOptionsValidator
)
from secrets_hunter.models import Disposition
from secrets_hunter.reporters.console_reporter import ConsoleReporter
from secrets_hunter.reporters.finding_presentation import present_findings
from secrets_hunter.reporters.finding_selection import select_for_reporting
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
        FindingSelectionOptionsValidator.validate(
            create_finding_selection_options(args)
        )
        FindingPresentationOptionsValidator.validate(
            create_finding_presentation_options(args)
        )
        source = args.source_factory(args)
        CLI_SCAN_MODE_REGISTRY.bind(source).validate()
        args.scan_source = source
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


def create_finding_selection_options(
    args: argparse.Namespace
) -> FindingSelectionOptions:
    return FindingSelectionOptions(
        min_confidence=args.min_confidence
    )


def create_finding_presentation_options(
    args: argparse.Namespace
) -> FindingPresentationOptions:
    return FindingPresentationOptions(
        reveal_findings=args.reveal_findings,
        truncate_long_matches=args.truncate_long_matches
    )


def run(args: argparse.Namespace) -> int:
    scan_options = create_scan_options(args)
    selection_options = create_finding_selection_options(args)
    presentation_options = create_finding_presentation_options(args)
    runtime = load_application_runtime(args.config)

    logging.basicConfig(
        level=args.log_level,
        format="%(asctime)s | %(levelname)s | %(module)s.%(funcName)s:%(lineno)d - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    progress_observer = TerminalScanProgressObserver()
    source = args.scan_source
    application = ScanApplication(
        runtime,
        scan_options,
        scan_modes=CLI_SCAN_MODE_REGISTRY
    )
    prepared_scan = application.prepare(source)
    started = time.monotonic()
    try:
        result = prepared_scan.run(
            progress_observer=progress_observer
        )
    finally:
        progress_observer.finish_progress_line()

    elapsed_seconds = time.monotonic() - started
    log_scan_result(result, elapsed_seconds)

    selected_findings = select_for_reporting(
        result.findings,
        selection_options
    )
    finding_views = present_findings(
        selected_findings,
        presentation_options
    )

    if result.complete or finding_views:
        log_findings_summary(
            finding_views,
            selection_options,
            total_detected_findings=len(result.findings)
        )

    if args.json_output:
        JSONReporter.export(
            prepared_scan.source_description,
            result,
            finding_views,
            args.json_output,
            elapsed_seconds=elapsed_seconds,
            selection_options=selection_options,
            presentation_options=presentation_options
        )
    elif args.sarif_output:
        SARIFReporter.export(finding_views, args.sarif_output)
    else:
        ConsoleReporter.format_report(finding_views)

    if not result.complete:
        return 1

    if args.fail_on_findings and any(
        finding.disposition is not Disposition.REJECT
        for finding in selected_findings
    ):
        return 2

    return 0
