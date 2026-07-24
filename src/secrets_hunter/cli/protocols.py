import argparse

from typing import Any, Protocol

from secrets_hunter.scanning.modes import ScanModeDefinition


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
    NAME: str
    SCAN_MODE: ScanModeDefinition[Any]

    def register(
        self,
        subparsers: SubparserRegistry,
        common_parser: argparse.ArgumentParser
    ) -> None:
        ...
