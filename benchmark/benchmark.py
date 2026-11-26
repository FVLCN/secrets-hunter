from pathlib import Path
import tempfile

from secrets_hunter.api import SecretsHunter
from secrets_hunter.application import FilesystemSource
from secrets_hunter.models import Disposition, Finding

from benchmark.loader import BenchmarkCaseLoader
from benchmark.models import (
    BenchmarkCase,
    BenchmarkEntry,
    NoFinding,
)
from benchmark.report import (
    BenchmarkCheck,
    BenchmarkObservation,
    BenchmarkReport,
    CheckStatus,
)


FindingKey = tuple[str, int, str]


class Benchmark:
    def __init__(
        self,
        *,
        case_loader: BenchmarkCaseLoader | None = None,
        hunter: SecretsHunter | None = None,
    ) -> None:
        self.case_loader = (
            case_loader if case_loader is not None else BenchmarkCaseLoader()
        )
        self.hunter = hunter

    def run(self) -> BenchmarkReport:
        cases = self.case_loader.load_cases()
        hunter = self.hunter if self.hunter is not None else SecretsHunter()
        observations = tuple(
            observation
            for case in cases
            for observation in self._scan_case(case, hunter)
        )
        return BenchmarkReport(
            cases=cases,
            observations=observations,
        )

    def _scan_case(
        self, case: BenchmarkCase, hunter: SecretsHunter
    ) -> tuple[BenchmarkObservation, ...]:
        files = case.file_contents
        with tempfile.TemporaryDirectory(prefix="secrets-hunter-benchmark-") as temp:
            scan_root = Path(temp).resolve()
            for relative_path, content in files.items():
                destination = scan_root / relative_path
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text(content, encoding="utf-8")

            result = hunter.scan(FilesystemSource(scan_root))
            if result.failures or result.skips or not result.complete:
                raise RuntimeError(
                    f"Incomplete scan for {case.case_path}: "
                    f"status={result.status}, failures={len(result.failures)}, "
                    f"skips={len(result.skips)}"
                )

            pending: dict[FindingKey, BenchmarkEntry] = {
                (entry.file, entry.line, entry.value): entry
                for entry in case.entries
            }

            observations: list[BenchmarkObservation] = []
            for finding in sorted(
                result.findings,
                key=lambda item: (
                    self._relative_path(item, scan_root),
                    item.location.line,
                    item.match,
                    item.kind.id,
                    item.confidence,
                ),
            ):
                relative_path = self._relative_path(finding, scan_root)
                key = (relative_path, finding.location.line, finding.match)
                entry = pending.pop(key, None)

                source_line = self._source_line(
                    files, relative_path, finding.location.line, finding
                )
                observations.append(
                    BenchmarkObservation(
                        case=case,
                        entry=entry,
                        file_path=relative_path,
                        line=finding.location.line,
                        source_line=source_line,
                        finding=finding,
                        checks=(
                            self._expectation_checks(entry, finding)
                            if entry is not None
                            else (
                                BenchmarkCheck(
                                    field="entry_match",
                                    status=CheckStatus.NOT_MET,
                                    expected="matched benchmark entry",
                                    actual="unmatched finding",
                                ),
                            )
                        ),
                    )
                )

            for entry in pending.values():
                observations.append(
                    BenchmarkObservation(
                        case=case,
                        entry=entry,
                        file_path=entry.file,
                        line=entry.line,
                        source_line=files[entry.file].splitlines()[entry.line - 1],
                        finding=None,
                        checks=self._expectation_checks(entry, None),
                    )
                )
            return tuple(observations)

    @staticmethod
    def _relative_path(finding: Finding, scan_root: Path) -> str:
        reported_path = Path(finding.location.locator)
        if reported_path.is_absolute():
            return reported_path.resolve().relative_to(scan_root).as_posix()
        return reported_path.as_posix()

    @staticmethod
    def _source_line(
        files: dict[str, str],
        relative_path: str,
        line_number: int,
        finding: Finding,
    ) -> str:
        source_lines = files.get(relative_path, "").splitlines()
        source_line = (
            source_lines[line_number - 1]
            if line_number <= len(source_lines)
            else ""
        )
        matched_lines = finding.match.splitlines()
        if len(matched_lines) > 1:
            continuation = " ".join(matched_lines[1:])
            source_line = f"{source_line} {continuation}"
        return source_line

    @staticmethod
    def _observed_disposition(
        finding: Finding | None,
    ) -> Disposition | NoFinding:
        return NoFinding.NONE if finding is None else finding.disposition

    @classmethod
    def _expectation_checks(
        cls, entry: BenchmarkEntry, finding: Finding | None
    ) -> tuple[BenchmarkCheck, ...]:
        checks: list[BenchmarkCheck] = []
        actual_disposition = cls._observed_disposition(finding)
        checks.append(
            BenchmarkCheck(
                field="disposition",
                status=(
                    CheckStatus.MET
                    if actual_disposition == entry.expected_disposition
                    else CheckStatus.NOT_MET
                ),
                expected=entry.expected_disposition.value,
                actual=actual_disposition.value,
            )
        )

        finding_expected = entry.expected_disposition is not NoFinding.NONE
        if finding_expected and finding is not None:
            actual_associated_name = finding.associated_name
            checks.append(
                BenchmarkCheck(
                    field="associated_name",
                    status=(
                        CheckStatus.MET
                        if actual_associated_name == entry.expected_associated_name
                        else CheckStatus.NOT_MET
                    ),
                    expected=entry.expected_associated_name,
                    actual=actual_associated_name,
                )
            )
        else:
            checks.append(
                BenchmarkCheck(
                    field="associated_name",
                    status=CheckStatus.NOT_APPLICABLE,
                    expected=entry.expected_associated_name,
                    actual=finding.associated_name if finding is not None else None,
                )
            )

        confidence_bounds = None
        confidence_status = CheckStatus.NOT_APPLICABLE

        bounds = entry.confidence_bounds
        if bounds is not None:
            confidence_min, confidence_max = bounds
            confidence_bounds = {"min": confidence_min, "max": confidence_max}

            if finding_expected and finding is not None:
                confidence_status = (
                    CheckStatus.MET
                    if confidence_min <= finding.confidence <= confidence_max
                    else CheckStatus.NOT_MET
                )

        checks.append(
            BenchmarkCheck(
                field="confidence",
                status=confidence_status,
                expected=confidence_bounds,
                actual=finding.confidence if finding is not None else None,
            )
        )
        return tuple(checks)

