from dataclasses import dataclass

from secrets_hunter.config import ScanOptions
from secrets_hunter.scanning.control import ScanControl
from secrets_hunter.scanning.executor import ScanExecutor
from secrets_hunter.scanning.source_scanner import SourceScanner


@dataclass(frozen=True)
class ScanSession:
    options: ScanOptions
    control: ScanControl
    executor: ScanExecutor
    source_scanner: SourceScanner
