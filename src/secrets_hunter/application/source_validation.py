from pathlib import Path

from secrets_hunter.application.sources import (
    DomainSource,
    FilesystemSource,
    GitHistorySource,
    ScanSource,
    TextSource,
    unsupported_scan_source
)
from secrets_hunter.scan_modes.domain.url import normalize_domain


class ScanSourceValidator:
    @classmethod
    def validate(cls, source: ScanSource) -> None:
        if isinstance(source, TextSource):
            cls._validate_text(source)
            return

        if isinstance(source, FilesystemSource):
            cls._validate_target(source.target)
            return

        if isinstance(source, GitHistorySource):
            cls._validate_git_history(source)
            return

        if isinstance(source, DomainSource):
            cls._validate_domain(source)
            return

        unsupported_scan_source(source)

    @staticmethod
    def _validate_text(source: TextSource) -> None:
        if not isinstance(source.content, str):
            raise TypeError("content must be a string")

        if not isinstance(source.name, str):
            raise TypeError("name must be a string")

        if not source.name.strip():
            raise ValueError("name must not be empty")

    @staticmethod
    def _validate_target(target: str | Path) -> None:
        if not isinstance(target, (str, Path)):
            raise TypeError("target must be a string or Path")

        if isinstance(target, str) and not target.strip():
            raise ValueError("target must not be empty")

    @classmethod
    def _validate_git_history(cls, source: GitHistorySource) -> None:
        cls._validate_target(source.target)

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

    @staticmethod
    def _validate_domain(source: DomainSource) -> None:
        if not isinstance(source.skip_tls_verify, bool):
            raise TypeError("skip_tls_verify must be a boolean")

        normalize_domain(source.domain)
