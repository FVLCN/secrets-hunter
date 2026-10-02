import logging

from threading import RLock
from typing import Callable, Protocol

from secrets_hunter.models import ScanResult


logger = logging.getLogger(__name__)


class ScanProgressObserver(Protocol):
    def scan_started(
        self,
        total_items: int | None,
        max_workers: int,
        *,
        single_source: bool
    ) -> None:
        ...

    def source_started(self, label: str) -> None:
        ...

    def source_progress(self, label: str, current_line: int) -> None:
        ...

    def item_completed(
        self,
        completed_items: int,
        total_items: int | None
    ) -> None:
        ...

    def scan_completed(self, result: ScanResult) -> None:
        ...


class NullScanProgressObserver:
    def scan_started(
        self,
        total_items: int | None,
        max_workers: int,
        *,
        single_source: bool
    ) -> None:
        pass

    def source_started(self, label: str) -> None:
        pass

    def source_progress(self, label: str, current_line: int) -> None:
        pass

    def item_completed(
        self,
        completed_items: int,
        total_items: int | None
    ) -> None:
        pass

    def scan_completed(self, result: ScanResult) -> None:
        pass


class IsolatedScanProgressObserver:
    def __init__(self, observer: ScanProgressObserver) -> None:
        self._observer = observer
        self._lock = RLock()
        self._enabled = True

    def _notify(
        self,
        callback_name: str,
        callback: Callable[..., None],
        *args: object,
        **kwargs: object
    ) -> None:
        with self._lock:
            if not self._enabled:
                return

            try:
                callback(*args, **kwargs)
            except Exception:
                self._enabled = False
                logger.exception(
                    "Scan progress observer disabled after %s() failed",
                    callback_name
                )

    def scan_started(
        self,
        total_items: int | None,
        max_workers: int,
        *,
        single_source: bool
    ) -> None:
        self._notify(
            "scan_started",
            self._observer.scan_started,
            total_items,
            max_workers,
            single_source=single_source
        )

    def source_started(self, label: str) -> None:
        self._notify(
            "source_started",
            self._observer.source_started,
            label
        )

    def source_progress(
        self,
        label: str,
        current_line: int
    ) -> None:
        self._notify(
            "source_progress",
            self._observer.source_progress,
            label,
            current_line
        )

    def item_completed(
        self,
        completed_items: int,
        total_items: int | None
    ) -> None:
        self._notify(
            "item_completed",
            self._observer.item_completed,
            completed_items,
            total_items
        )

    def scan_completed(self, result: ScanResult) -> None:
        self._notify(
            "scan_completed",
            self._observer.scan_completed,
            result
        )
