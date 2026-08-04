import logging
import math
import sys

from typing import TextIO, override

from secrets_hunter.models import ScanFailureKind, ScanResult, ScanStatus
from secrets_hunter.scanning.progress import ScanProgressObserver


logger = logging.getLogger(__name__)

_SCAN_STATUS_MESSAGES = {
    ScanStatus.COMPLETE: "Scan completed.",
    ScanStatus.PARTIAL: "Scan completed with errors.",
    ScanStatus.FAILED: "Scan failed.",
    ScanStatus.ABORTED: "Scan aborted."
}


def _count_label(count: int, singular: str) -> str:
    label = singular if count == 1 else f"{singular}s"
    return f"{count} {label}"


class TerminalScanProgressObserver(ScanProgressObserver):
    FILE_PROGRESS_STEP = 100

    def __init__(
        self,
        bar_width: int = 40,
        stream: TextIO | None = None,
    ) -> None:
        self.bar_width = bar_width
        self.stream = stream if stream is not None else sys.stderr
        self.single_source = False
        self.progress_line_open = False
        self.last_percent = -1
        self.last_source_line = 0
        self.last_rendered_source_line = 0

    @override
    def scan_started(
        self,
        total_items: int | None,
        max_workers: int,
        *,
        single_source: bool
    ) -> None:
        self.single_source = single_source
        self.last_percent = -1
        self.last_source_line = 0
        self.last_rendered_source_line = 0

        if total_items == 0:
            logger.warning("No sources found to scan.")
        elif total_items is None:
            logger.info(
                "Discovering and scanning sources with "
                f"{_count_label(max_workers, 'worker')}...\n"
            )
        elif not single_source:
            logger.info(
                f"Scanning {_count_label(total_items, 'source')} with "
                f"{_count_label(max_workers, 'worker')}...\n"
            )

    @override
    def source_started(self, label: str) -> None:
        if self.single_source:
            logger.info(f"Scanning {label}...")

    @override
    def source_progress(self, label: str, current_line: int) -> None:
        if not self.single_source:
            return

        self.last_source_line = current_line
        if (
            self.last_rendered_source_line
            and current_line % self.FILE_PROGRESS_STEP != 0
        ):
            return

        self._render_source_progress(current_line)

    @override
    def item_completed(
        self,
        completed_items: int,
        total_items: int | None
    ) -> None:
        if self.single_source:
            return

        if total_items is None:
            self._write_progress(
                f"\rScanned {_count_label(completed_items, 'source')}..."
            )
            return

        ratio = completed_items / total_items
        percent = int(ratio * 100)

        if percent == self.last_percent:
            return

        self.last_percent = percent
        filled = math.floor(self.bar_width * ratio)
        bar = "█" * filled + "-" * (self.bar_width - filled)
        self._write_progress(
            f"\r[{bar}] {percent:3d}% ({completed_items}/{total_items})"
        )

    @override
    def scan_completed(self, result: ScanResult) -> None:
        if (
            self.single_source
            and self.last_source_line
            and self.last_rendered_source_line != self.last_source_line
        ):
            self._render_source_progress(self.last_source_line)

        self.finish_progress_line(
            add_spacing=not self.single_source or result.aborted
        )

        for failure in result.failures:
            if failure.kind is ScanFailureKind.INTERNAL:
                error_name = failure.exception_type or "InternalError"
                logger.error(
                    f"Internal error scanning {failure.label}: "
                    f"{error_name}: {failure.message}"
                )
                if failure.diagnostic:
                    logger.debug(
                        "Internal error traceback for %s:\n%s",
                        failure.label,
                        failure.diagnostic.rstrip()
                    )
            else:
                logger.error(
                    f"Error scanning {failure.label}: {failure.message}"
                )

        logger.info(_SCAN_STATUS_MESSAGES[result.status])

    def finish_progress_line(self, *, add_spacing: bool = True) -> None:
        if not self.progress_line_open:
            return

        self.stream.write("\r\n")
        if add_spacing:
            self.stream.write("\r\n")
        self.stream.flush()
        self.progress_line_open = False

    def _render_source_progress(self, current_line: int) -> None:
        self.last_rendered_source_line = current_line
        self._write_progress(
            f"\rScanned through line {current_line}..."
        )

    def _write_progress(self, text: str) -> None:
        self.stream.write(text)
        self.stream.flush()
        self.progress_line_open = True
