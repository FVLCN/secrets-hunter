import argparse

from secrets_hunter.application import GitHistorySource
from secrets_hunter.scanning.modes.git_history.mode import GIT_HISTORY_MODE


NAMES = ("git",)
SCAN_MODE = GIT_HISTORY_MODE


def create_source(args: argparse.Namespace) -> GitHistorySource:
    if args.git_revset is None:
        raise ValueError("--revset is required for --source git")

    return GitHistorySource(
        "." if args.target is None else args.target,
        args.git_revset,
        args.git_max_count
    )
