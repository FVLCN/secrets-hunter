from secrets_hunter.scanning.scanner import BaseScanner

from ..contracts import (
    ScannerContext,
    ScanModeDefinition,
    SourceParameters
)
from ..path_validation import validate_path_target
from ..sources import FilesystemSource
from .collector import FilesystemCollector
from .reader import FileReader
from .scanner import FilesystemScanner


def validate_filesystem_source(source: FilesystemSource) -> None:
    validate_path_target(source.target)


def create_filesystem_scanner(
    source: FilesystemSource,
    context: ScannerContext
) -> BaseScanner:
    return FilesystemScanner(
        context.session,
        FilesystemCollector(
            context.path_filter,
            context.content_validator
        ),
        FileReader(context.source_text_reader),
        str(source.target)
    )


def describe_filesystem_source(
    source: FilesystemSource
) -> SourceParameters:
    return {
        "target": str(source.target)
    }


FILESYSTEM_MODE = ScanModeDefinition(
    mode_id="filesystem",
    source_type=FilesystemSource,
    validate_source=validate_filesystem_source,
    create_scanner=create_filesystem_scanner,
    describe_source=describe_filesystem_source
)
