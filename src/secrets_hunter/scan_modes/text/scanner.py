from typing import override

from secrets_hunter.models import ScanResult
from secrets_hunter.scanning.scanner import BaseScanner
from secrets_hunter.scanning.session import ScanSession
from secrets_hunter.scanning.source_identity import SourcePathResolver
from secrets_hunter.scanning.text_reader import SourceTextReader
from secrets_hunter.scanning.work import ScanWorkItem, ScanWorkPlan


class TextScanner(BaseScanner):
    def __init__(
        self,
        session: ScanSession,
        source_text_reader: SourceTextReader,
        content: str,
        source_name: str
    ) -> None:
        super().__init__(session)
        self.source_text_reader = source_text_reader
        self.content = content
        self.source_name = source_name
        self.source_path_resolver = SourcePathResolver.for_target(".")

    @override
    def create_work_plan(self) -> ScanWorkPlan:
        return ScanWorkPlan(
            label=self.source_name,
            events=(
                ScanWorkItem(
                    label=self.source_name,
                    run=self.scan_text
                ),
            ),
            total_items=1
        )

    def scan_text(self) -> ScanResult:
        return self.session.source_scanner.scan(
            self.source_text_reader.text_to_lines(self.content),
            self.source_path_resolver.identify(self.source_name)
        )
