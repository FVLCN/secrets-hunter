import argparse

from secrets_hunter.config import load_runtime_config
from secrets_hunter.reporters.runtime_cfg_reporter import RuntimeConfigReporter

from ..options import add_config_option
from ..protocols import SubparserRegistry
from ..validation import validate_config_options


NAME = "showconfig"
SECTIONS = ["ignore_files", "ignore_extensions", "ignore_dirs"]


def register(subparsers: SubparserRegistry) -> None:
    parser = subparsers.add_parser(
        NAME,
        help="display the current runtime configuration",
    )
    add_config_option(parser)
    parser.add_argument(
        "sections",
        nargs="*",
        help="specific sections to display; shows all if omitted.",
        choices=SECTIONS,
    )
    parser.set_defaults(command_handler=run, command_validator=validate)


def validate(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    validate_config_options(parser, args)


def run(args: argparse.Namespace) -> int:
    runtime_cfg = load_runtime_config(args.config)
    RuntimeConfigReporter.pretty_runtime_cfg(runtime_cfg, args.sections)
    return 0
