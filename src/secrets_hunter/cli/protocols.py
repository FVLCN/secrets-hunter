import argparse

from typing import Any, Protocol

from secrets_hunter.scanning.modes import ScanModeDefinition, ScanSource


class SubparserRegistry(Protocol):
    def add_parser(
        self,
        name: str,
        **kwargs: object
    ) -> argparse.ArgumentParser:
        ...


class CommandModule(Protocol):
    NAME: str

    def register(self, subparsers: SubparserRegistry) -> None:
        ...


class ScanSourceAdapter(Protocol):
    NAMES: tuple[str, ...]
    SCAN_MODE: ScanModeDefinition[Any]

    def create_source(
        self,
        args: argparse.Namespace
    ) -> ScanSource:
        ...
