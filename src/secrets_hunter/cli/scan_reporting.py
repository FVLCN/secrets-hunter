import logging

from collections import Counter

from secrets_hunter.config import FindingSelectionOptions
from secrets_hunter.models import ScanResult, Severity
from secrets_hunter.reporters.finding_view import FindingView


logger = logging.getLogger(__name__)


def log_scan_result(result: ScanResult, elapsed: float) -> None:
    minutes = int(elapsed // 60)
    seconds = int(elapsed % 60)
    milliseconds = int((elapsed % 1) * 1000)
    duration = (
        f"{minutes}m {seconds}s {milliseconds}ms"
        if minutes
        else f"{seconds}s {milliseconds}ms"
    )
    logger.info(f"Scan duration: {duration}")

    if not result.complete and not result.aborted:
        total_items = (
            str(result.total_items)
            if result.total_items is not None
            else "unknown"
        )
        logger.warning(
            f"Scan status: {result.status.value}. "
            f"{result.successful_items}/{total_items} scan item(s) "
            f"completed successfully; {len(result.failures)} failure(s)."
        )


def log_findings_summary(
    findings: list[FindingView],
    selection_options: FindingSelectionOptions,
    *,
    total_detected_findings: int
) -> None:
    severity_counts = Counter(finding.severity for finding in findings)
    total_findings = len(findings)

    if total_findings == 0:
        if total_detected_findings:
            logger.info(
                "No findings met the minimum confidence threshold"
            )
        else:
            logger.info("No secrets found")
    elif total_findings == 1:
        finding = findings[0]
        logger.info(f"1 {finding.severity.lower()} severity secret was found")
    else:
        severity_summary = " ".join(
            f"{severity_counts[severity]} {severity.lower()},"
            for severity in Severity
            if severity_counts[severity]
        ).removesuffix(",")
        logger.info(f"Found {total_findings} secrets: {severity_summary}")

    if total_findings > 0 and not selection_options.min_confidence:
        logger.info(
            "Showing all findings, including rejected ones. "
            "Use the --min-confidence flag to exclude them from the report."
        )
