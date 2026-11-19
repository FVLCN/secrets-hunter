import argparse

from secrets_hunter.application import DomainSource
from secrets_hunter.scanning.modes.domain.mode import DOMAIN_MODE


NAMES = ("domain",)
SCAN_MODE = DOMAIN_MODE


def create_source(args: argparse.Namespace) -> DomainSource:
    if args.target is None:
        raise ValueError("--target is required for --source domain")

    return DomainSource(
        args.target,
        skip_tls_verify=args.skip_tls_verify
    )
