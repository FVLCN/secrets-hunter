from dataclasses import fields
from pathlib import Path
import tomllib
from typing import Any

from benchmark.models import (
    BenchmarkCase,
    BenchmarkCategory,
    BenchmarkEntry,
    BenchmarkFile,
    ExpectedDisposition,
    NoFinding,
)
from secrets_hunter.models import Disposition


def _reject_unknown_fields(
    values: dict[str, Any],
    model: type[BenchmarkCase] | type[BenchmarkFile] | type[BenchmarkEntry],
    location: str,
) -> None:
    allowed = {
        item.name
        for item in fields(model)
        if item.metadata.get("toml_input", True)
    }
    unknown = sorted(set(values) - allowed)
    if unknown:
        names = ", ".join(repr(name) for name in unknown)
        raise ValueError(f"{location} has unknown field(s): {names}")


class BenchmarkCaseLoader:
    def __init__(self, cases_root: Path | None = None) -> None:
        default_root = Path(__file__).resolve().parent / "cases"
        self.cases_root = cases_root if cases_root is not None else default_root
        self.benchmark_root = self.cases_root.parent

    def load_cases(self) -> tuple[BenchmarkCase, ...]:
        cases: list[BenchmarkCase] = []
        seen_case_ids: set[str] = set()

        for category in BenchmarkCategory:
            category_root = self.cases_root / category.value
            for path in sorted(category_root.rglob("*.toml")):
                raw_case = self._load_toml(path)
                if not raw_case:
                    continue

                case_path = path.relative_to(self.benchmark_root).as_posix()
                _reject_unknown_fields(raw_case, BenchmarkCase, case_path)
                case_id = self._string(
                    raw_case.get("case_id", path.stem), "case_id", case_path
                )
                if case_id in seen_case_ids:
                    raise ValueError(f"Duplicate case_id: {case_id}")
                seen_case_ids.add(case_id)

                files = self._load_files(raw_case, case_path)
                entries = self._load_entries(
                    raw_case,
                    case_path,
                    files=files,
                )
                cases.append(
                    BenchmarkCase(
                        case_id=case_id,
                        description=self._string(
                            raw_case.get("description", ""), "description", case_path
                        ),
                        category=category,
                        case_path=case_path,
                        files=files,
                        entries=entries,
                    )
                )

        if not cases:
            raise ValueError(f"No TOML cases found under {self.cases_root}")
        return tuple(cases)

    @staticmethod
    def _load_toml(path: Path) -> dict[str, Any]:
        with path.open("rb") as stream:
            return tomllib.load(stream)

    def _load_files(
        self, raw_case: dict[str, Any], case_path: str
    ) -> tuple[BenchmarkFile, ...]:
        raw_files = raw_case.get("files", [])
        if not isinstance(raw_files, list):
            raise ValueError(f"{case_path} files must be an array")

        files: list[BenchmarkFile] = []
        seen_paths: set[str] = set()
        for index, raw_file in enumerate(raw_files):
            if not isinstance(raw_file, dict):
                raise ValueError(f"{case_path} files[{index}] must be a table")
            _reject_unknown_fields(
                raw_file, BenchmarkFile, f"{case_path} files[{index}]"
            )
            source_path = self._string(raw_file.get("path"), "file path", case_path)
            relative_path = Path(source_path)
            if relative_path.is_absolute() or ".." in relative_path.parts:
                raise ValueError(
                    f"{case_path} contains unsafe file path {source_path!r}"
                )

            key = relative_path.as_posix()
            if key in seen_paths:
                raise ValueError(f"{case_path} contains duplicate file path {key!r}")
            seen_paths.add(key)
            files.append(
                BenchmarkFile(
                    path=key,
                    content=self._string(
                        raw_file.get("content"), "file content", case_path
                    ),
                )
            )

        if not files:
            raise ValueError(f"{case_path} has no [[files]] entries")
        return tuple(files)

    def _load_entries(
        self,
        raw_case: dict[str, Any],
        case_path: str,
        *,
        files: tuple[BenchmarkFile, ...],
    ) -> tuple[BenchmarkEntry, ...]:
        raw_entries = raw_case.get("entries", [])
        if not isinstance(raw_entries, list):
            raise ValueError(f"{case_path} entries must be an array")
        if not raw_entries:
            raise ValueError(f"{case_path} has no [[entries]] entries")

        file_contents = {
            source_file.path: source_file.content for source_file in files
        }
        entries: list[BenchmarkEntry] = []
        seen_entry_ids: set[str] = set()
        seen_targets: dict[tuple[str, int, str], str] = {}
        for index, raw_entry in enumerate(raw_entries):
            if not isinstance(raw_entry, dict):
                raise ValueError(f"{case_path} entries[{index}] must be a table")
            entry_location = f"{case_path} entries[{index}]"
            _reject_unknown_fields(raw_entry, BenchmarkEntry, entry_location)

            entry_id = self._string(raw_entry.get("id"), "entry id", case_path)
            if entry_id in seen_entry_ids:
                raise ValueError(
                    f"Duplicate entry id {entry_id!r} in {case_path}"
                )
            seen_entry_ids.add(entry_id)

            raw_disposition = raw_entry.get("expected_disposition")
            if not isinstance(raw_disposition, str):
                raise ValueError(
                    f"{case_path}:{entry_id} has invalid expected_disposition"
                )
            try:
                expected_disposition: ExpectedDisposition = (
                    NoFinding.NONE
                    if raw_disposition == NoFinding.NONE.value
                    else Disposition(raw_disposition)
                )
            except ValueError as error:
                raise ValueError(
                    f"{case_path}:{entry_id} has invalid expected_disposition"
                ) from error

            if "expected_associated_name" not in raw_entry:
                raise ValueError(
                    f"{case_path}:{entry_id} is missing expected_associated_name"
                )
            expected_associated_name = self._string(
                raw_entry["expected_associated_name"],
                "expected_associated_name",
                case_path,
            ) or None

            known_problem = raw_entry.get("known_problem", False)
            if not isinstance(known_problem, bool):
                raise ValueError(
                    f"{case_path}:{entry_id} known_problem must be a boolean"
                )

            file_path = self._string(raw_entry.get("file"), "entry file", case_path)
            if file_path not in file_contents:
                raise ValueError(
                    f"{case_path}:{entry_id} refers to missing file {file_path!r}"
                )
            line_number = raw_entry.get("line")
            if isinstance(line_number, bool) or not isinstance(line_number, int):
                raise ValueError(f"{case_path}:{entry_id} has invalid line number")

            value = self._string(raw_entry.get("value"), "entry value", case_path)
            content = file_contents[file_path]
            if not 1 <= line_number <= len(content.splitlines()):
                raise ValueError(f"{case_path}:{entry_id} has line out of range")
            value_start = content.find(value)
            if (
                not value
                or value_start < 0
                or content.find(value, value_start + 1) >= 0
                or content.count("\n", 0, value_start) + 1 != line_number
            ):
                raise ValueError(
                    f"{case_path}:{entry_id} value must occur exactly once starting "
                    "on its declared line"
                )

            target = (file_path, line_number, value)
            if target in seen_targets:
                raise ValueError(
                    f"{case_path}:{entry_id} targets the same file, line, and value "
                    f"as entry {seen_targets[target]!r}"
                )
            seen_targets[target] = entry_id

            try:
                entry = BenchmarkEntry(
                    id=entry_id,
                    file=file_path,
                    line=line_number,
                    value=value,
                    expected_disposition=expected_disposition,
                    expected_associated_name=expected_associated_name,
                    known_problem=known_problem,
                    confidence_min=raw_entry.get("confidence_min"),
                    confidence_max=raw_entry.get("confidence_max"),
                )
            except ValueError as error:
                raise ValueError(f"{case_path}:{entry_id} has {error}") from error
            entries.append(entry)
        return tuple(entries)

    @staticmethod
    def _string(value: Any, field: str, case_path: str) -> str:
        if not isinstance(value, str):
            raise ValueError(f"{case_path} {field} must be a string")
        return value

