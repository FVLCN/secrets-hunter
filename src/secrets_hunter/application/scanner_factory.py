from secrets_hunter.application.composition import (
    compose_path_filter,
    compose_scan_session
)
from secrets_hunter.application.sources import (
    DomainSource,
    FilesystemSource,
    GitHistorySource,
    ScanSource,
    TextSource,
    unsupported_scan_source
)
from secrets_hunter.config import ScanOptions
from secrets_hunter.runtime import ApplicationRuntime
from secrets_hunter.scan_modes.domain.scanner import DomainScanner
from secrets_hunter.scan_modes.filesystem.collector import FilesystemCollector
from secrets_hunter.scan_modes.filesystem.reader import FileReader
from secrets_hunter.scan_modes.filesystem.scanner import FilesystemScanner
from secrets_hunter.scan_modes.git_history.scanner import GitHistoryScanner
from secrets_hunter.scan_modes.text.scanner import TextScanner
from secrets_hunter.scanning.cancellation import ScanCancellation
from secrets_hunter.scanning.content_safety import (
    DEFAULT_CONTENT_SAFETY_POLICY
)
from secrets_hunter.scanning.content_validator import TextContentValidator
from secrets_hunter.scanning.progress import ScanProgressObserver
from secrets_hunter.scanning.scanner import BaseScanner
from secrets_hunter.scanning.text_reader import SourceTextReader


def create_scanner(
    source: ScanSource,
    runtime: ApplicationRuntime,
    scan_options: ScanOptions,
    *,
    cancellation: ScanCancellation | None = None,
    progress_observer: ScanProgressObserver | None = None
) -> BaseScanner:
    session = compose_scan_session(
        runtime,
        scan_options,
        cancellation=cancellation,
        progress=progress_observer
    )
    content_safety = DEFAULT_CONTENT_SAFETY_POLICY
    content_validator = TextContentValidator(content_safety)
    source_text_reader = SourceTextReader(content_safety)

    if isinstance(source, TextSource):
        return TextScanner(
            session,
            source_text_reader,
            source.content,
            source.name
        )

    if isinstance(source, FilesystemSource):
        return FilesystemScanner(
            session,
            FilesystemCollector(
                compose_path_filter(runtime),
                content_validator
            ),
            FileReader(source_text_reader),
            str(source.target)
        )

    if isinstance(source, GitHistorySource):
        return GitHistoryScanner(
            session,
            compose_path_filter(runtime),
            content_validator,
            source_text_reader,
            str(source.target),
            source.revset,
            source.max_count
        )

    if isinstance(source, DomainSource):
        return DomainScanner(
            session,
            content_validator,
            source_text_reader,
            source.domain,
            skip_tls_verify=source.skip_tls_verify
        )

    return unsupported_scan_source(source)
