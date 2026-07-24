from secrets_hunter.scanning.scanner import BaseScanner

from ..contracts import (
    ScannerContext,
    ScanModeDefinition,
    SourceParameters
)
from ..sources import DomainSource
from .scanner import DomainScanner
from .url import normalize_domain


def validate_domain_source(source: DomainSource) -> None:
    if not isinstance(source.skip_tls_verify, bool):
        raise TypeError("skip_tls_verify must be a boolean")

    normalize_domain(source.domain)


def create_domain_scanner(
    source: DomainSource,
    context: ScannerContext
) -> BaseScanner:
    return DomainScanner(
        context.session,
        context.content_validator,
        context.source_text_reader,
        source.domain,
        skip_tls_verify=source.skip_tls_verify
    )


def describe_domain_source(source: DomainSource) -> SourceParameters:
    return {
        "domain": source.domain,
        "skip_tls_verify": source.skip_tls_verify
    }


DOMAIN_MODE = ScanModeDefinition(
    mode_id="domain",
    source_type=DomainSource,
    validate_source=validate_domain_source,
    create_scanner=create_domain_scanner,
    describe_source=describe_domain_source
)
