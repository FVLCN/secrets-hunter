from pathlib import Path
from typing import Self

from secrets_hunter.application import (
    ScanApplication,
    ScanSource
)
from secrets_hunter.config import ScanOptions
from secrets_hunter.models import ScanResult
from secrets_hunter.runtime import ApplicationRuntime, load_application_runtime
from secrets_hunter.scanning import ScanCancellation, ScanProgressObserver


class SecretsHunter:
    def __init__(
        self,
        runtime: ApplicationRuntime | None = None,
        scan_options: ScanOptions | None = None
    ) -> None:
        application_runtime = (
            runtime
            if runtime is not None
            else load_application_runtime()
        )
        self._application = ScanApplication(
            application_runtime,
            scan_options
        )

    @classmethod
    def from_config(
        cls,
        user_configs: list[str | Path] | None = None,
        scan_options: ScanOptions | None = None
    ) -> Self:
        return cls(
            load_application_runtime(user_configs),
            scan_options
        )

    def scan(
        self,
        source: ScanSource,
        *,
        cancellation: ScanCancellation | None = None,
        progress_observer: ScanProgressObserver | None = None
    ) -> ScanResult:
        return self._application.scan(
            source,
            cancellation=cancellation,
            progress_observer=progress_observer
        )
