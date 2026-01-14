import sys
import argparse
import logging

from secrets_hunter.scanner import SecretsHunter
from secrets_hunter.config.settings import ScannerConfig
from secrets_hunter.reporters.console_reporter import ConsoleReporter
from secrets_hunter.reporters.json_reporter import JSONReporter


def parse_arguments():
    parser = argparse.ArgumentParser(
        description='Detect secrets and sensitive information in your codebase',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        'target',
        nargs='?',
        default='.',
        help='File or directory to scan (default: current directory)'
    )

    parser.add_argument(
        '--json',
        dest='json_output',
        metavar='FILE',
        help='Export results to JSON file'
    )

    parser.add_argument(
        '--hex-entropy',
        type=float,
        default=ScannerConfig.HEX_ENTROPY_THRESHOLD,
        help=f'Hex entropy threshold (default: {ScannerConfig.HEX_ENTROPY_THRESHOLD})'
    )

    parser.add_argument(
        '--b64-entropy',
        type=float,
        default=ScannerConfig.BASE64_ENTROPY_THRESHOLD,
        help=f'Base64 entropy threshold (default: {ScannerConfig.BASE64_ENTROPY_THRESHOLD})'
    )

    parser.add_argument(
        '--min-length',
        type=int,
        default=ScannerConfig.MIN_STRING_LENGTH,
        help=f'Minimum string length (default: {ScannerConfig.MIN_STRING_LENGTH})'
    )

    parser.add_argument(
        '--log-level',
        type=str,
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        default=ScannerConfig.LOG_LEVEL,
        help=f'Log level (default: {ScannerConfig.LOG_LEVEL})'
    )

    parser.add_argument(
        '--workers',
        type=int,
        default=ScannerConfig.MAX_WORKERS,
        help=f'Number of parallel workers (default: {ScannerConfig.MAX_WORKERS})'
    )

    return parser.parse_args()


def main():
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
    print(logo_ascii)

    args = parse_arguments()

    config = ScannerConfig()
    config.HEX_ENTROPY_THRESHOLD = args.hex_entropy
    config.BASE64_ENTROPY_THRESHOLD = args.b64_entropy
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
