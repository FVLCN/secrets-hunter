from dataclasses import dataclass

from secrets_hunter.scanning.cancellation import ScanCancellation
from secrets_hunter.scanning.progress import ScanProgressObserver


@dataclass(frozen=True)
class ScanControl:
    cancellation: ScanCancellation
    progress: ScanProgressObserver
