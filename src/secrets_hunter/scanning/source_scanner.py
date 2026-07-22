from collections.abc import Iterable
from secrets_hunter.detection.engine import DetectionEngine
from secrets_hunter.detection.fragmenter.lines_reader import PEMAwareLinesReader
from secrets_hunter.models import Finding, ScanFailure, ScanResult
from secrets_hunter.scanning.control import ScanControl
from secrets_hunter.scanning.failures import source_scan_failure
from secrets_hunter.scanning.source_identity import SourceIdentity
from secrets_hunter.scanning.text_reader import SourceReadLimitError


class SourceScanner:
    def __init__(
        self,
        detection_engine: DetectionEngine,
        lines_reader: PEMAwareLinesReader,
        control: ScanControl
    ) -> None:
        self.detection_engine = detection_engine
        self.lines_reader = lines_reader
        self.control = control

    def scan(
        self,
        lines: Iterable[str] | None,
        source: SourceIdentity
    ) -> ScanResult:
        findings: list[Finding] = []
        display_label = source.display_label
        self.control.progress.source_started(display_label)

        if lines is None:
            return ScanResult(
                total_items=1,
                attempted_items=1,
                failures=(
                    ScanFailure(
                        label=display_label,
                        message="Failed to read source"
                    ),
                )
            )

        try:
            for source_fragment in self.lines_reader.read(lines):
                if self.control.cancellation.cancelled:
                    return ScanResult(
                        findings=tuple(findings),
                        total_items=1,
                        attempted_items=1,
                        aborted=True
                    )

                findings.extend(
                    self.detection_engine.scan_fragment(
                        source_fragment,
                        source.finding_path
                    )
                )
                self.control.progress.source_progress(
                    display_label,
                    source_fragment.end_line
                )
        except (OSError, SourceReadLimitError) as error:
            return ScanResult(
                findings=tuple(findings),
                total_items=1,
                attempted_items=1,
                failures=(
                    source_scan_failure(display_label, str(error)),
                )
            )

        if self.control.cancellation.cancelled:
            return ScanResult(
                findings=tuple(findings),
                total_items=1,
                attempted_items=1,
                aborted=True
            )

        return ScanResult(
            findings=tuple(findings),
            total_items=1,
            attempted_items=1,
            successful_items=1
        )
