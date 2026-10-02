from collections.abc import Callable, Iterable
from dataclasses import dataclass

from secrets_hunter.models.scan_result import ScanFailure, ScanResult


@dataclass(frozen=True)
class ScanWorkItem:
    label: str
    run: Callable[[], ScanResult]


type ScanWorkEvent = ScanWorkItem | ScanFailure


@dataclass(frozen=True)
class ScanWorkPlan:
    label: str
    events: Iterable[ScanWorkEvent]
    total_items: int | None = None

    def __post_init__(self) -> None:
        if self.total_items is not None and self.total_items < 0:
            raise ValueError("total_items must not be negative")
