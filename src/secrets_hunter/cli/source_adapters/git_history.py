import argparse

from secrets_hunter.application import GitHistorySource

from ..protocols import SubparserRegistry


NAME = "git"


def register(
    subparsers: SubparserRegistry,
    common_parser: argparse.ArgumentParser
) -> None:
    parser = subparsers.add_parser(
        NAME,
        parents=[common_parser],
        help="scan file contents from git history"
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=".",
        help="repository, file, or directory to scan (default: current directory)"
    )
    parser.add_argument(
        "--revset",
        dest="git_revset",
        type=str,
        required=True,
        metavar="REVSET",
        help="scan file contents from commits selected by a git revision expression"
    )
    parser.add_argument(
        "--max-count",
        dest="git_max_count",
        type=int,
        default=None,
        metavar="N",
        help="limit number of commits selected by --revset"
    )
    parser.set_defaults(source_factory=create_source)


def create_source(args: argparse.Namespace) -> GitHistorySource:
    return GitHistorySource(
        args.target,
        args.git_revset,
        args.git_max_count
    )
