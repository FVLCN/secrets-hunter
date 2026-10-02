import logging

from collections.abc import Iterator
from pathlib import Path
from typing import override

from secrets_hunter.models import (
    ScanFailure,
    ScanResult
)
from secrets_hunter.scanning.modes.filesystem.collector import FilesystemCollector
from secrets_hunter.scanning.modes.filesystem.reader import FileReader
from secrets_hunter.scanning.scanner import BaseScanner
from secrets_hunter.scanning.session import ScanSession
from secrets_hunter.scanning.source_identity import SourcePathResolver
from secrets_hunter.scanning.work import (
    ScanWorkEvent,
    ScanWorkItem,
    ScanWorkPlan
)


logger = logging.getLogger(__name__)


class FilesystemScanner(BaseScanner):
    def __init__(
        self,
        session: ScanSession,
        file_collector: FilesystemCollector,
        file_reader: FileReader,
        target: str
    ) -> None:
        super().__init__(session)
        self.file_collector = file_collector
        self.file_reader = file_reader
        self.target = target
        self.target_path = Path(target)
        self.source_path_resolver = (
            SourcePathResolver.for_target(target)
            if self.target_path.is_file() or self.target_path.is_dir()
            else SourcePathResolver()
        )

    @override
    def create_work_plan(self) -> ScanWorkPlan:
        display_path = Path.cwd() if self.target == "." else self.target
        logger.info(f"Collecting files from {display_path}...")
        single_file = self.target_path.is_file()

        return ScanWorkPlan(
            label=self.target,
            events=self._work_events(),
            total_items=1 if single_file else None
        )

    def _work_events(self) -> Iterator[ScanWorkEvent]:
        for entry in self.file_collector.iter_entries(self.target_path):
            if isinstance(entry, ScanFailure):
                yield entry
            else:
                filepath = entry
                yield ScanWorkItem(
                    label=str(filepath),
                    run=lambda filepath=filepath: self.scan_file(filepath)
                )

    def scan_file(self, filepath: Path) -> ScanResult:
        lines = self.file_reader.read_file(filepath)
        return self.session.source_scanner.scan(
            lines,
            self.source_path_resolver.identify_resolved_file(filepath)
        )
