import argparse
from pathlib import Path

from secrets_hunter.application import FilesystemSource
from secrets_hunter.scanning.modes.filesystem.mode import FILESYSTEM_MODE


NAMES = ("file", "directory")
SCAN_MODE = FILESYSTEM_MODE


def create_source(args: argparse.Namespace) -> FilesystemSource:
    if args.source == "file" and args.target is None:
        raise ValueError("--target is required for --source file")

    target = "." if args.target is None else args.target
    path = Path(target)
    if args.source == "file" and not path.is_file():
        raise ValueError("--target must be an existing file for --source file")
    if args.source == "directory" and not path.is_dir():
        raise ValueError(
            "--target must be an existing directory for --source directory"
        )

    return FilesystemSource(target)
