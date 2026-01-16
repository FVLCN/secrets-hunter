import sys
import os
import argparse
import logging

from pathlib import Path

from secrets_hunter.scanner import SecretsHunter
from secrets_hunter.config import settings
from secrets_hunter.config.settings import ScannerConfig
from secrets_hunter.reporters.console_reporter import ConsoleReporter
from secrets_hunter.reporters.json_reporter import JSONReporter


logo_ascii = r"""
     ________ ___      ___ ___       ________  ________      
    |\  _____\\  \    /  /|\  \     |\   ____\|\   ___  \    
    \ \  \__/\ \  \  /  / | \  \    \ \  \___|\ \  \\ \  \   
     \ \   __\\ \  \/  / / \ \  \    \ \  \    \ \  \\ \  \  
      \ \  \_| \ \    / /   \ \  \____\ \  \____\ \  \\ \  \ 
       \ \__\   \ \__/ /     \ \_______\ \_______\ \__\\ \__\
        \|__|    \|__|/       \|_______|\|_______|\|__| \|__|
                       +==============+                      
                       |Secrets Hunter|                      
                       +==============+                      
"""


class CLI:
    def __init__(self):
        self.parser = argparse.ArgumentParser(
            description="Detect secrets and sensitive information in your codebase",
            formatter_class=argparse.RawDescriptionHelpFormatter
        )
        self.add_args()

    def add_args(self):
        p = self.parser

        p.add_argument(
            "target",
            nargs="?",
            default=".",
            help="File or directory to scan (default: current directory)",
        )

        p.add_argument(
            '--json',
            dest='json_output',
            metavar='FILE',
            help='Export results to JSON file'
        )

        p.add_argument(
            '--hex-entropy',
            type=float,
            default=ScannerConfig.HEX_ENTROPY_THRESHOLD,
            help=f'Hex entropy threshold (default: {ScannerConfig.HEX_ENTROPY_THRESHOLD})'
        )

        p.add_argument(
            '--b64-entropy',
            type=float,
            default=ScannerConfig.B64_ENTROPY_THRESHOLD,
            help=f'Base64 entropy threshold (default: {ScannerConfig.B64_ENTROPY_THRESHOLD})'
        )

        p.add_argument(
            '--min-length',
            type=int,
            default=ScannerConfig.MIN_STRING_LENGTH,
            help=f'Minimum string length (default: {ScannerConfig.MIN_STRING_LENGTH})'
        )

        p.add_argument(
            '--workers',
            type=int,
            default=ScannerConfig.MAX_WORKERS,
            help=f'Number of parallel workers (default: {ScannerConfig.MAX_WORKERS})'
        )

        p.add_argument(
            '--log-level',
            type=str,
            choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
            default=ScannerConfig.LOG_LEVEL,
            help=f'Log level (default: {ScannerConfig.LOG_LEVEL})'
        )

    def parse(self):
        args = self.parser.parse_args()

        validators = [
            (self.validate_entropy, [args.hex_entropy, "hex-entropy", settings.HEX_ENTROPY_MAX]),
            (self.validate_entropy, [args.b64_entropy, "b64-entropy", settings.B64_ENTROPY_MAX]),
            (self.validate_min_length, [args.min_length]),
            (self.validate_workers, [args.workers]),
            (self.validate_json, [args.json_output])
        ]

        for fn, params in validators:
            fn(*params)

        return args

    def validate_entropy(self, value, name, v_max):
        if not 0.0 <= value <= v_max:
            self.parser.error(f"--{name} must be between 0.0 and {v_max}")

    def validate_min_length(self, value):
        if value <= 0:
            self.parser.error("--min-length must be > 0")

    def validate_workers(self, value):
        max_workers = (os.cpu_count() or 1) * settings.MAX_WORKERS_MULTIPLIER

        if value <= 0:
            self.parser.error("--workers must be > 0")
        if value > max_workers:
            self.parser.error(f"--workers cannot exceed {max_workers}")

    def validate_json(self, path):
        if not path:
            return

        parent = Path(path).parent

        if not parent.exists() or not parent.is_dir():
            self.parser.error(f"--json parent dir does not exist: {parent}")


def main():
    print(logo_ascii)

    cli = CLI()
    args = cli.parse()

    config = ScannerConfig()
    config.HEX_ENTROPY_THRESHOLD = args.hex_entropy
    config.B64_ENTROPY_THRESHOLD = args.b64_entropy
    config.MIN_STRING_LENGTH = args.min_length
    config.MAX_WORKERS = args.workers

    logging.basicConfig(
        level=args.log_level,
        format='%(asctime)s | %(levelname)s | %(module)s.%(funcName)s:%(lineno)d - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    scanner = SecretsHunter(config)
    findings, success = scanner.scan(args.target)

    if not success:
        sys.exit(1)

    if args.json_output:
        JSONReporter.export(findings, args.json_output)
    else:
        ConsoleReporter.format_report(findings)

    sys.exit(0)


if __name__ == '__main__':
    main()
