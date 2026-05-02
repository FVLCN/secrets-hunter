import sys
import argparse
import logging

from secrets_hunter import __version__
from secrets_hunter.scanner import SecretsHunter
from secrets_hunter.config import CLIArgs, CLIDefaults, load_runtime_config
from secrets_hunter.validators import CLIArgsValidator
from secrets_hunter.models import Confidence
from secrets_hunter.reporters.console_reporter import ConsoleReporter
from secrets_hunter.reporters.json_reporter import JSONReporter
from secrets_hunter.reporters.sarif_reporter import SARIFReporter
from secrets_hunter.reporters.runtime_cfg_reporter import RuntimeConfigReporter

logo_ascii_filled = r"""

    ███████╗██╗   ██╗██╗      ██████╗███╗   ██╗
    ██╔════╝██║   ██║██║     ██╔════╝████╗  ██║
    █████╗  ██║   ██║██║     ██║     ██╔██╗ ██║
    ██╔══╝  ╚██╗ ██╔╝██║     ██║     ██║╚██╗██║
    ██║      ╚████╔╝ ███████╗╚██████╗██║ ╚████║
    ╚═╝       ╚═══╝  ╚══════╝ ╚═════╝╚═╝  ╚═══╝
"""

logo_ascii_hollow = r"""
   ________ ___      ___ ___       ________  ________      
  |\  _____\\  \    /  /|\  \     |\   ____\|\   ___  \    
  \ \  \__/\ \  \  /  / | \  \    \ \  \___|\ \  \\ \  \   
   \ \   __\\ \  \/  / / \ \  \    \ \  \    \ \  \\ \  \  
    \ \  \_| \ \    / /   \ \  \____\ \  \____\ \  \\ \  \ 
     \ \__\   \ \__/ /     \ \_______\ \_______\ \__\\ \__\
      \|__|    \|__|/       \|_______|\|_______|\|__| \|__|
"""

scan_args = {
    "target": {
        "nargs": "?",
        "default": ".",
        "help": "file or directory to scan (default: current directory)",
    },
    "--reveal-findings": {
        "action": "store_true",
        "default": CLIDefaults.REVEAL_FINDINGS,
        "help": f"reveal findings in output (default: {CLIDefaults.REVEAL_FINDINGS})"
    },
    "--config": {
        "action": "append",
        "default": None,
        "metavar": "FILE",
        "help": "path to TOML overlay config. Can be used multiple times."
    },
    "--json": {
        "dest": "json_output",
        "metavar": "FILE",
        "help": "export results to JSON file"
    },
    "--sarif": {
        "dest": "sarif_output",
        "metavar": "FILE",
        "help": "export results to SARIF file"
    },
    "--hex-entropy": {
        "type": float,
        "default": CLIDefaults.HEX_ENTROPY_THRESHOLD,
        "help": f"hex entropy threshold (default: {CLIDefaults.HEX_ENTROPY_THRESHOLD})"
    },
    "--b64-entropy": {
        "type": float,
        "default": CLIDefaults.B64_ENTROPY_THRESHOLD,
        "help": f"base64 entropy threshold (default: {CLIDefaults.B64_ENTROPY_THRESHOLD})"
    },
    "--min-length": {
        "type": int,
        "default": CLIDefaults.MIN_STRING_LENGTH,
        "help": f"minimum string length (default: {CLIDefaults.MIN_STRING_LENGTH})"
    },
    "--workers": {
        "type": int,
        "default": CLIDefaults.MAX_WORKERS,
        "help": f"number of parallel workers (default: {CLIDefaults.MAX_WORKERS})"
    },
    "--log-level": {
        "type": str,
        "choices": ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        "default": CLIDefaults.LOG_LEVEL,
        "help": f"log level (default: {CLIDefaults.LOG_LEVEL})"
    },
    "--min-confidence": {
        "type": int,
        "default": CLIDefaults.MIN_CONFIDENCE,
        "help": f"minimum confidence of findings to display (default: {CLIDefaults.MIN_CONFIDENCE})"
    },
    "--fail-on-findings": {
        "action": "store_true",
        "default": CLIDefaults.FAIL_ON_FINDINGS,
        "help": "exit with code 2 if report contains non-rejected findings"
    },
    "--truncate-long-matches": {
        "action": "store_true",
        "dest": "truncate_long_matches",
        "default": CLIDefaults.TRUNCATE_LONG_MATCHES,
        "help": "truncate long finding matches in output"
    }
}

showconfig_args = {
    "--config": scan_args["--config"],
    "sections": {
        "nargs": "*",
        "help": "specific sections to display; shows all if omitted.",
        "choices": [
            'secret_patterns',
            'exclude_patterns',
            'secret_keywords',
            'exclude_keywords',
            'assignment_patterns',
            'ignore_files',
            'ignore_extensions',
            'ignore_dirs'
        ]
    }
}


def display_logo_with_version(logo, version):
    version_text = f"Secrets Hunter v{version}"
    version_length = len(version_text)

    logo_lines = logo.strip('\n').split('\n')
    logo_width = max(len(line) for line in logo_lines)

    padding = (logo_width - version_length)
    version_ascii = f"""\n{' ' * padding}{version_text}\n"""
    print(logo + version_ascii)


class CLI:
    def __init__(self):
        self.parser = argparse.ArgumentParser(
            description="The Secrets Scanner that respects your time",
            formatter_class=argparse.RawDescriptionHelpFormatter
        )
        self.parser.add_argument(
            '--version',
            action='version',
            version=f'%(prog)s v{__version__}'
        )
        self.add_args()

    @staticmethod
    def fill_args(parser, args_dict):
        for arg_name, kwargs in args_dict.items():
            parser.add_argument(arg_name, **kwargs)

    def add_args(self):
        subparsers = self.parser.add_subparsers(dest='command', help='available commands')
        scan_parser = subparsers.add_parser(
            'scan',
            help='scan files for secrets (default command)',
            formatter_class=argparse.RawDescriptionHelpFormatter
        )
        self.fill_args(scan_parser, scan_args)
        showconfig_parser = subparsers.add_parser(
            'showconfig',
            help='display the current runtime configuration'
        )
        self.fill_args(showconfig_parser, showconfig_args)

    def parse(self):
        known_args = ['scan', 'showconfig', '-h', '--help', '--version']

        # If no args or first arg isn't a subcommand, inject 'scan'
        if len(sys.argv) == 1 or (len(sys.argv) > 1 and sys.argv[1] not in known_args):
            sys.argv.insert(1, 'scan')

        args = self.parser.parse_args()
        args_validator = CLIArgsValidator(self.parser)
        args_validator.validate_common_args(args)

        if args.command == 'showconfig':
            return args

        args_validator.validate_scan_args(args)
        return args


def main():
    if '--version' not in sys.argv:
        import random
        logo = logo_ascii_filled if random.random() < 0.05 else logo_ascii_hollow
        display_logo_with_version(logo, __version__)

    cli = CLI()
    args = cli.parse()

    if args.command == 'showconfig':
        runtime_cfg = load_runtime_config(args.config)
        RuntimeConfigReporter.pretty_runtime_cfg(runtime_cfg, args.sections)
        sys.exit(0)

    cli_args = CLIArgs.from_argparse(args)
    runtime_cfg = load_runtime_config(args.config)

    logging.basicConfig(
        level=args.log_level,
        format='%(asctime)s | %(levelname)s | %(module)s.%(funcName)s:%(lineno)d - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    scanner = SecretsHunter(runtime_cfg, cli_args)
    findings, success = scanner.scan(args.target)

    if not success:
        sys.exit(1)

    if args.json_output:
        JSONReporter.export(findings, args.json_output)
    elif args.sarif_output:
        SARIFReporter.export(findings, args.sarif_output)
    else:
        ConsoleReporter.format_report(findings)

    if cli_args.fail_on_findings:
        for finding in findings:
            if finding.confidence > Confidence.REJECTED:
                sys.exit(2)

    sys.exit(0)


if __name__ == '__main__':
    main()
