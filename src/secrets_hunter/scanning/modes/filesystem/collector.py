from collections.abc import Iterator
from enum import StrEnum
from pathlib import Path

from secrets_hunter.models import ScanFailure
from secrets_hunter.scanning.content_validator import TextContentValidator
from secrets_hunter.scanning.failures import source_scan_failure
from secrets_hunter.scanning.path_filter import PathFilter


class _FileRejection(StrEnum):
    NOT_REGULAR = "Scan target is not a regular file"
    NOT_TEXT = "Scan target is not a text file"


type _FileValidation = Path | _FileRejection
type FilesystemEntry = Path | ScanFailure


class FilesystemCollector:
    def __init__(
        self,
        path_filter: PathFilter,
        content_validator: TextContentValidator
    ) -> None:
        self.path_filter = path_filter
        self.content_validator = content_validator

    def iter_entries(self, target: Path) -> Iterator[FilesystemEntry]:
        try:
            resolved_root = target.resolve(strict=True)
        except (OSError, RuntimeError) as error:
            yield source_scan_failure(str(target), str(error))
            return

        if resolved_root.is_file():
            try:
                validation = self._validate_file(resolved_root)
            except (OSError, RuntimeError) as error:
                yield source_scan_failure(str(target), str(error))
                return

            if isinstance(validation, _FileRejection):
                yield source_scan_failure(str(target), validation.value)
            else:
                yield validation
            return

        visited_paths: set[Path] = set()
        visited_directories: set[tuple[int, int]] = set()
        pending_failures: list[ScanFailure] = []

        def record_walk_error(error: OSError) -> None:
            label = str(error.filename or resolved_root)
            pending_failures.append(source_scan_failure(label, str(error)))

        for directory, directory_names, file_names in resolved_root.walk(
            top_down=True,
            on_error=record_walk_error,
            follow_symlinks=False
        ):
            yield from pending_failures
            pending_failures.clear()

            directory_failures: list[ScanFailure] = []
            if not self._enter_directory(
                directory,
                resolved_root,
                visited_paths,
                visited_directories,
                directory_failures
            ):
                yield from directory_failures
                directory_names.clear()
                continue

            directory_names[:] = self._safe_directory_names(
                directory,
                directory_names,
                resolved_root,
                directory_failures
            )
            yield from directory_failures

            for file_name in sorted(file_names):
                file_path = directory / file_name
                file_failures: list[ScanFailure] = []
                resolved_file = self._safe_file(
                    file_path,
                    resolved_root,
                    file_failures
                )
                yield from file_failures
                if resolved_file is not None:
                    yield resolved_file

        yield from pending_failures

    def _enter_directory(
        self,
        directory: Path,
        resolved_root: Path,
        visited_paths: set[Path],
        visited_directories: set[tuple[int, int]],
        failures: list[ScanFailure]
    ) -> bool:
        try:
            resolved_directory = directory.resolve(strict=True)
            if not resolved_directory.is_relative_to(resolved_root):
                return False

            stat_result = resolved_directory.stat()
        except (OSError, RuntimeError) as error:
            failures.append(source_scan_failure(str(directory), str(error)))
            return False

        if resolved_directory in visited_paths:
            return False

        identity = (
            (stat_result.st_dev, stat_result.st_ino)
            if stat_result.st_ino
            else None
        )
        if identity is not None and identity in visited_directories:
            return False

        visited_paths.add(resolved_directory)
        if identity is not None:
            visited_directories.add(identity)

        return True

    def _safe_directory_names(
        self,
        directory: Path,
        directory_names: list[str],
        resolved_root: Path,
        failures: list[ScanFailure]
    ) -> list[str]:
        safe_names: list[str] = []

        for directory_name in sorted(directory_names):
            directory_path = directory / directory_name

            try:
                if directory_path.is_symlink() or directory_path.is_junction():
                    continue

                resolved_directory = directory_path.resolve(strict=True)
                if not resolved_directory.is_relative_to(resolved_root):
                    continue

                relative_path = resolved_directory.relative_to(resolved_root)
                if self.path_filter.is_ignored_directory(relative_path):
                    continue
            except (OSError, RuntimeError) as error:
                failures.append(
                    source_scan_failure(str(directory_path), str(error))
                )
                continue

            safe_names.append(directory_name)

        return safe_names

    def _safe_file(
        self,
        file_path: Path,
        resolved_root: Path,
        failures: list[ScanFailure]
    ) -> Path | None:
        try:
            if file_path.is_symlink() or file_path.is_junction():
                return None

            resolved_file = file_path.resolve(strict=True)
            if not resolved_file.is_relative_to(resolved_root):
                return None

            relative_path = resolved_file.relative_to(resolved_root)
            if self.path_filter.is_ignored_path(relative_path):
                return None

            validation = self._validate_file(resolved_file)
        except (OSError, RuntimeError) as error:
            failures.append(source_scan_failure(str(file_path), str(error)))
            return None

        return validation if isinstance(validation, Path) else None

    def _validate_file(
        self,
        resolved_file: Path
    ) -> _FileValidation:
        if not resolved_file.is_file():
            return _FileRejection.NOT_REGULAR

        if not self.content_validator.is_text_file(resolved_file):
            return _FileRejection.NOT_TEXT

        return resolved_file
