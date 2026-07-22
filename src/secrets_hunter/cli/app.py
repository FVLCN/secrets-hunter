import argparse
import sys
from collections.abc import Sequence

from secrets_hunter._version import __version__

from .banner import display_random_logo
from .commands import COMMAND_NAMES, register_commands


ROOT_OPTIONS = frozenset({"-h", "--help", "--version"})


def normalize_argv(argv: Sequence[str]) -> list[str]:
    normalized = list(argv)
    if not normalized:
        return ["scan", "files"]
    if normalized[0] not in COMMAND_NAMES | ROOT_OPTIONS:
        return ["scan", "files", *normalized]
    return normalized


class CLI:
    def __init__(self) -> None:
        self.parser = argparse.ArgumentParser(
            description="The Secrets Scanner that respects your time",
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        self.parser.add_argument(
            "--version",
            action="version",
            version=f"%(prog)s v{__version__}",
        )
        subparsers = self.parser.add_subparsers(
            dest="command",
            help="available commands",
        )
        register_commands(subparsers)

    def parse(self, argv: Sequence[str] | None = None) -> argparse.Namespace:
        raw_argv = sys.argv[1:] if argv is None else argv
        args = self.parser.parse_args(normalize_argv(raw_argv))
        args.command_validator(self.parser, args)
        return args


def run(argv: Sequence[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)

    if "--version" not in raw_argv:
        display_random_logo(__version__)

    args = CLI().parse(raw_argv)
    return args.command_handler(args)


def main(argv: Sequence[str] | None = None) -> int:
    return run(argv)
