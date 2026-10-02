import argparse
from pathlib import Path


def validate_config_options(
    parser: argparse.ArgumentParser,
    args: argparse.Namespace
) -> None:
    for configured_path in args.config or []:
        path = Path(configured_path).expanduser().resolve()
        if not path.exists() or not path.is_file():
            parser.error(f"--config file does not exist: {path}")
        if path.suffix.lower() != ".toml":
            parser.error(f"--config must be a .toml file: {path}")


def validate_output_options(
    parser: argparse.ArgumentParser,
    args: argparse.Namespace
) -> None:
    if args.json_output and args.sarif_output:
        parser.error("--json and --sarif cannot be used together")

    _validate_output_file(parser, args.json_output, "json")
    _validate_output_file(parser, args.sarif_output, "sarif")


def _validate_output_file(
    parser: argparse.ArgumentParser,
    path: str | None,
    flag_name: str
) -> None:
    if not path:
        return

    parent = Path(path).parent
    if not parent.exists() or not parent.is_dir():
        parser.error(f"--{flag_name} parent dir does not exist: {parent}")
