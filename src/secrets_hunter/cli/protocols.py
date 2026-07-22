import argparse

from typing import Protocol


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

    def register(
        self,
        subparsers: SubparserRegistry,
        common_parser: argparse.ArgumentParser
    ) -> None:
        ...
