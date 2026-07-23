from secrets_hunter.application.scanner_factory import create_scanner
from secrets_hunter.application.source_validation import ScanSourceValidator
from secrets_hunter.application.sources import ScanSource
from secrets_hunter.config import ScanOptions
from secrets_hunter.config.validation import ScanOptionsValidator
from secrets_hunter.models import ScanResult
from secrets_hunter.runtime import ApplicationRuntime
from secrets_hunter.scanning.cancellation import ScanCancellation
from secrets_hunter.scanning.progress import ScanProgressObserver


class ScanApplication:
    def __init__(
        self,
        runtime: ApplicationRuntime,
        scan_options: ScanOptions | None = None
    ) -> None:
        self.runtime = runtime
        self.scan_options = scan_options or ScanOptions()
        ScanOptionsValidator.validate(self.scan_options)

    def scan(
        self,
        source: ScanSource,
        *,
        cancellation: ScanCancellation | None = None,
        progress_observer: ScanProgressObserver | None = None
    ) -> ScanResult:
        ScanSourceValidator.validate(source)
        scanner = create_scanner(
            source,
            self.runtime,
            self.scan_options,
            cancellation=cancellation,
            progress_observer=progress_observer
        )
        return scanner.scan()
