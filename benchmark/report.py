from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
import hashlib
import json

from secrets_hunter.models import DEFAULT_TOOL_INFO, Finding, ToolInfo

from benchmark.models import BenchmarkCase, BenchmarkEntry


def checksum_case_data(cases: Iterable[BenchmarkCase]) -> str:
    canonical_cases = [
        asdict(case)
        for case in sorted(cases, key=lambda item: item.case_path)
    ]
    canonical_json = json.dumps(
        canonical_cases,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical_json).hexdigest()


class CheckStatus(StrEnum):
    MET = "met"
    NOT_MET = "not_met"
    NOT_APPLICABLE = "not_applicable"


@dataclass(frozen=True, slots=True)
class BenchmarkCheck:
    field: str
    status: CheckStatus
    expected: object
    actual: object


@dataclass(frozen=True, slots=True)
class BenchmarkObservation:
    case: BenchmarkCase
    entry: BenchmarkEntry | None
    file_path: str
    line: int
    source_line: str
    finding: Finding | None
    checks: tuple[BenchmarkCheck, ...]

    @property
    def expectation_met(self) -> bool:
        return all(check.status is not CheckStatus.NOT_MET for check in self.checks)

    @property
    def mismatches(self) -> tuple[BenchmarkCheck, ...]:
        return tuple(
            check
            for check in self.checks
            if check.status is CheckStatus.NOT_MET
        )

    @property
    def known_problem(self) -> bool:
        return self.entry is not None and self.entry.known_problem

    @property
    def unexpected(self) -> bool:
        return self.entry is None

    @property
    def fails_benchmark(self) -> bool:
        return not self.known_problem and (
            self.unexpected or not self.expectation_met
        )


@dataclass(frozen=True, slots=True)
class BenchmarkReport:
    cases: tuple[BenchmarkCase, ...]
    observations: tuple[BenchmarkObservation, ...]
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    tool: ToolInfo = DEFAULT_TOOL_INFO

    @property
    def passed(self) -> bool:
        return not any(
            observation.fails_benchmark
            for observation in self.observations
        )

    @property
    def failing_expectations(self) -> int:
        return sum(
            observation.entry is not None and not observation.expectation_met
            for observation in self.observations
        )

    @property
    def known_problem_failures(self) -> int:
        return sum(
            observation.known_problem and not observation.expectation_met
            for observation in self.observations
        )

    @property
    def unexpected_findings(self) -> int:
        return sum(observation.unexpected for observation in self.observations)

    @property
    def entry_count(self) -> int:
        return sum(len(case.entries) for case in self.cases)

    @property
    def case_data_sha256(self) -> str:
        return checksum_case_data(self.cases)
