from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Self, cast

from secrets_hunter.immutability import frozen_mapping
from secrets_hunter.scanning.scanner import BaseScanner

from .contracts import (
    ScannerContext,
    ScanModeDefinition,
    ScanSourceDescription
)
from .sources import ScanSource


type RegisteredScanMode = ScanModeDefinition[Any]


@dataclass(frozen=True)
class BoundScanMode[S: ScanSource]:
    definition: ScanModeDefinition[S]
    source: S

    def validate(self) -> None:
        self.definition.validate_source(self.source)

    def create_scanner(self, context: ScannerContext) -> BaseScanner:
        return self.definition.create_scanner(self.source, context)

    def describe(self) -> ScanSourceDescription:
        return ScanSourceDescription(
            kind=self.definition.mode_id,
            parameters=self.definition.describe_source(self.source)
        )


@dataclass(frozen=True, init=False)
class ScanModeRegistry:
    _modes: tuple[RegisteredScanMode, ...]
    _modes_by_source_type: Mapping[type[ScanSource], RegisteredScanMode]

    def __init__(self, modes: Iterable[RegisteredScanMode]) -> None:
        registered = tuple(modes)
        if not registered:
            raise ValueError("scan mode registry must not be empty")

        modes_by_id: dict[str, RegisteredScanMode] = {}
        modes_by_source_type: dict[
            type[ScanSource],
            RegisteredScanMode
        ] = {}

        for mode in registered:
            if not isinstance(mode, ScanModeDefinition):
                raise TypeError(
                    "scan mode registry entries must be "
                    "ScanModeDefinition instances"
                )

            if mode.mode_id in modes_by_id:
                raise ValueError(f"duplicate scan mode ID: {mode.mode_id}")

            if mode.source_type in modes_by_source_type:
                raise ValueError(
                    "duplicate scan source type: "
                    f"{mode.source_type.__name__}"
                )

            modes_by_id[mode.mode_id] = mode
            modes_by_source_type[mode.source_type] = mode

        object.__setattr__(self, "_modes", registered)
        object.__setattr__(
            self,
            "_modes_by_source_type",
            frozen_mapping(modes_by_source_type)
        )

    @property
    def modes(self) -> tuple[RegisteredScanMode, ...]:
        return self._modes

    def bind[S: ScanSource](self, source: S) -> BoundScanMode[S]:
        definition = self._modes_by_source_type.get(type(source))
        if definition is None:
            raise TypeError(
                f"unsupported scan source: {type(source).__name__}"
            )

        return BoundScanMode(
            cast(ScanModeDefinition[S], definition),
            source
        )

    def with_mode(self, mode: RegisteredScanMode) -> Self:
        return type(self)((*self._modes, mode))
