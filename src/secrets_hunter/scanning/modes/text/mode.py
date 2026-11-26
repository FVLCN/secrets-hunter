from secrets_hunter.scanning.scanner import BaseScanner

from ..contracts import (
    ScannerContext,
    ScanModeDefinition,
    SourceParameters
)
from ..sources import TextSource
from .scanner import TextScanner


def validate_text_source(source: TextSource) -> None:
    if not isinstance(source.content, str):
        raise TypeError("content must be a string")

    if not isinstance(source.name, str):
        raise TypeError("name must be a string")

    if not source.name.strip():
        raise ValueError("name must not be empty")


def create_text_scanner(
    source: TextSource,
    context: ScannerContext
) -> BaseScanner:
    return TextScanner(
        context.session,
        context.source_text_reader,
        source.content,
        source.name
    )


def describe_text_source(source: TextSource) -> SourceParameters:
    return {
        "name": source.name
    }


TEXT_MODE = ScanModeDefinition(
    mode_id="text",
    source_type=TextSource,
    validate_source=validate_text_source,
    create_scanner=create_text_scanner,
    describe_source=describe_text_source
)
