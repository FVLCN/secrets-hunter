import json
import logging

from secrets_hunter import __version__
from secrets_hunter.config import (
    FindingPresentationOptions,
    FindingSelectionOptions
)
from secrets_hunter.models import ScanFailure, ScanResult
from secrets_hunter.reporters.finding_view import FindingView
from secrets_hunter.scanning.modes import ScanSourceDescription

logger = logging.getLogger(__name__)


def _scan_failure_to_dict(failure: ScanFailure) -> dict[str, object]:
    data: dict[str, object] = {
        "kind": failure.kind.value,
        "label": failure.label,
        "message": failure.message
    }

    if failure.exception_type is not None:
        data["exception_type"] = failure.exception_type

    if failure.diagnostic is not None:
        data["diagnostic"] = failure.diagnostic

    return data


class JSONReporter:
    @staticmethod
    def build_report(
        source: ScanSourceDescription,
        result: ScanResult,
        findings: list[FindingView],
        *,
        elapsed_seconds: float,
        selection_options: FindingSelectionOptions,
        presentation_options: FindingPresentationOptions
    ) -> dict[str, object]:
        if elapsed_seconds < 0:
            raise ValueError("elapsed_seconds must not be negative")

        return {
            "schema_version": 1,
            "tool": {
                "name": "secrets-hunter",
                "version": __version__
            },
            "scan": {
                "source": {
                    "kind": source.kind,
                    **source.parameters
                },
                "status": result.status.value,
                "duration_seconds": round(elapsed_seconds, 6),
                "items": {
                    "total": result.total_items,
                    "attempted": result.attempted_items,
                    "successful": result.successful_items
                },
                "failures": [
                    _scan_failure_to_dict(failure)
                    for failure in result.failures
                ]
            },
            "reporting": {
                "min_confidence": selection_options.min_confidence,
                "findings_revealed": presentation_options.reveal_findings,
                "long_matches_truncated": (
                    presentation_options.truncate_long_matches
                ),
                "detected_findings": len(result.findings),
                "reported_findings": len(findings)
            },
            "findings": [
                finding.to_dict()
                for finding in findings
            ]
        }

    @classmethod
    def export(
        cls,
        source: ScanSourceDescription,
        result: ScanResult,
        findings: list[FindingView],
        output_file: str,
        *,
        elapsed_seconds: float,
        selection_options: FindingSelectionOptions,
        presentation_options: FindingPresentationOptions
    ) -> None:
        logger.info(f"Exporting results to {output_file}...")
        report = cls.build_report(
            source,
            result,
            findings,
            elapsed_seconds=elapsed_seconds,
            selection_options=selection_options,
            presentation_options=presentation_options
        )

        with open(output_file, "w", encoding="utf-8") as output:
            json.dump(report, output, indent=4)
            output.write("\n")

        logger.info(f"Results exported to {output_file}")
