from dataclasses import dataclass

from secrets_hunter.application.composition import compose_scanner_context
from secrets_hunter.config import ScanOptions
from secrets_hunter.config.validation import ScanOptionsValidator
from secrets_hunter.models import ScanResult
from secrets_hunter.runtime import ApplicationRuntime
from secrets_hunter.scanning.cancellation import ScanCancellation
from secrets_hunter.scanning.modes import (
    BoundScanMode,
    ScanModeRegistry,
    ScanSource,
    ScanSourceDescription
)
from secrets_hunter.scanning.progress import ScanProgressObserver


@dataclass(frozen=True)
class PreparedScan[S: ScanSource]:
    runtime: ApplicationRuntime
    scan_options: ScanOptions
    mode: BoundScanMode[S]

    @property
    def source_description(self) -> ScanSourceDescription:
        return self.mode.describe()

    def run(
        self,
        *,
        cancellation: ScanCancellation | None = None,
        progress_observer: ScanProgressObserver | None = None
    ) -> ScanResult:
        context = compose_scanner_context(
            self.runtime,
            self.scan_options,
            cancellation=cancellation,
            progress=progress_observer
        )
        return self.mode.create_scanner(context).scan()


class ScanApplication:
    def __init__(
        self,
        runtime: ApplicationRuntime,
        scan_options: ScanOptions | None = None,
        *,
        scan_modes: ScanModeRegistry
    ) -> None:
        self.runtime = runtime
        self.scan_options = scan_options or ScanOptions()
        self.scan_modes = scan_modes
        ScanOptionsValidator.validate(self.scan_options)

    def prepare[S: ScanSource](self, source: S) -> PreparedScan[S]:
        mode = self.scan_modes.bind(source)
        mode.validate()
        return PreparedScan(
            runtime=self.runtime,
            scan_options=self.scan_options,
            mode=mode
        )

    def scan[S: ScanSource](
        self,
        source: S,
        *,
        cancellation: ScanCancellation | None = None,
        progress_observer: ScanProgressObserver | None = None
    ) -> ScanResult:
        return self.prepare(source).run(
            cancellation=cancellation,
            progress_observer=progress_observer
        )
