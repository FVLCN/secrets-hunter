from collections.abc import Iterable
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Self

from .finding import Finding


class ScanStatus(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"
    ABORTED = "aborted"


class ScanFailureKind(StrEnum):
    SOURCE = "source"
    INTERNAL = "internal"


@dataclass(frozen=True)
class ScanFailure:
    label: str
    message: str
    kind: ScanFailureKind = ScanFailureKind.SOURCE
    exception_type: str | None = None
    diagnostic: str | None = None


@dataclass(frozen=True)
class ScanResult:
    findings: tuple[Finding, ...] = ()
    total_items: int | None = 0
    attempted_items: int = 0
    successful_items: int = 0
    failures: tuple[ScanFailure, ...] = ()
    aborted: bool = False

    def __post_init__(self) -> None:
        if not 0 <= self.successful_items <= self.attempted_items:
            raise ValueError(
                "Scan item counts must satisfy "
                "0 <= successful_items <= attempted_items"
            )

        if (
            self.total_items is not None
            and self.attempted_items > self.total_items
        ):
            raise ValueError(
                "attempted_items must not exceed total_items"
            )

    @property
    def status(self) -> ScanStatus:
        if self.aborted:
            return ScanStatus.ABORTED

        if (
            self.total_items is not None
            and not self.failures
            and self.successful_items == self.total_items
        ):
            return ScanStatus.COMPLETE

        if self.successful_items:
            return ScanStatus.PARTIAL

        return ScanStatus.FAILED

    @property
    def complete(self) -> bool:
        return self.status is ScanStatus.COMPLETE

    def with_findings(self, findings: Iterable[Finding]) -> Self:
        return replace(self, findings=tuple(findings))
