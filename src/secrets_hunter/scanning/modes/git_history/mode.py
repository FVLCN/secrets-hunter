from secrets_hunter.scanning.scanner import BaseScanner

from ..contracts import (
    ScannerContext,
    ScanModeDefinition,
    SourceParameters
)
from ..path_validation import validate_path_target
from ..sources import GitHistorySource
from .scanner import GitHistoryScanner


def validate_git_history_source(source: GitHistorySource) -> None:
    validate_path_target(source.target)

    if not isinstance(source.revset, str):
        raise TypeError("revset must be a string")

    if not source.revset.strip():
        raise ValueError("revset must not be empty")

    if source.max_count is not None:
        if isinstance(source.max_count, bool) or not isinstance(
            source.max_count,
            int
        ):
            raise TypeError("max_count must be an integer")

        if source.max_count <= 0:
            raise ValueError("max_count must be greater than zero")


def create_git_history_scanner(
    source: GitHistorySource,
    context: ScannerContext
) -> BaseScanner:
    return GitHistoryScanner(
        context.session,
        context.path_filter,
        context.content_validator,
        context.source_text_reader,
        str(source.target),
        source.revset,
        source.max_count
    )


def describe_git_history_source(
    source: GitHistorySource
) -> SourceParameters:
    return {
        "target": str(source.target),
        "revset": source.revset,
        "max_count": source.max_count
    }


GIT_HISTORY_MODE = ScanModeDefinition(
    mode_id="git",
    source_type=GitHistorySource,
    validate_source=validate_git_history_source,
    create_scanner=create_git_history_scanner,
    describe_source=describe_git_history_source
)
