import argparse

from secrets_hunter.application import DomainSource

from ..defaults import DEFAULT_SKIP_TLS_VERIFY
from ..protocols import SubparserRegistry


NAME = "domain"


def register(
    subparsers: SubparserRegistry,
    common_parser: argparse.ArgumentParser
) -> None:
    parser = subparsers.add_parser(
        NAME,
        parents=[common_parser],
        help="scan common sensitive paths on a domain"
    )
    parser.add_argument(
        "domain",
        type=str,
        metavar="DOMAIN",
        help="scan common sensitive URLs on a domain"
    )
    parser.add_argument(
        "--skip-tls-verify",
        action="store_true",
        default=DEFAULT_SKIP_TLS_VERIFY,
        help="skip TLS certificate verification for domain scans"
    )
    parser.set_defaults(source_factory=create_source)


def create_source(args: argparse.Namespace) -> DomainSource:
    return DomainSource(
        args.domain,
        skip_tls_verify=args.skip_tls_verify
    )
