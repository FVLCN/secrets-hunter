import argparse

from secrets_hunter.application import FilesystemSource

from ..protocols import SubparserRegistry


NAME = "files"


def register(
    subparsers: SubparserRegistry,
    common_parser: argparse.ArgumentParser
) -> None:
    parser = subparsers.add_parser(
        NAME,
        parents=[common_parser],
        help="scan files or directories"
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=".",
        help="file or directory to scan (default: current directory)"
    )
    parser.set_defaults(source_factory=create_source)


def create_source(args: argparse.Namespace) -> FilesystemSource:
    return FilesystemSource(args.target)
