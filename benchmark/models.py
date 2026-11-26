from dataclasses import dataclass, field
from enum import StrEnum

from secrets_hunter.models import Disposition


class BenchmarkCategory(StrEnum):
    POSITIVE = "positive"
    NEGATIVE = "negative"


class NoFinding(StrEnum):
    NONE = "no_finding"


ExpectedDisposition = Disposition | NoFinding


@dataclass(frozen=True, slots=True)
class BenchmarkFile:
    path: str
    content: str


@dataclass(frozen=True, slots=True)
class BenchmarkEntry:
    id: str
    file: str
    line: int
    value: str
    expected_disposition: ExpectedDisposition
    expected_associated_name: str | None
    known_problem: bool = False
    confidence_min: int | None = None
    confidence_max: int | None = None

    def __post_init__(self) -> None:
        bounds = self.confidence_bounds
        if (
            any(
                bound is not None
                and (isinstance(bound, bool) or not isinstance(bound, int))
                for bound in (self.confidence_min, self.confidence_max)
            )
            or (bounds is not None and not 0 <= bounds[0] <= bounds[1] <= 100)
        ):
            raise ValueError("invalid confidence bounds")

    @property
    def confidence_bounds(self) -> tuple[int, int] | None:
        if self.confidence_min is None and self.confidence_max is None:
            return None
        return (
            0 if self.confidence_min is None else self.confidence_min,
            100 if self.confidence_max is None else self.confidence_max,
        )


@dataclass(frozen=True, slots=True)
class BenchmarkCase:
    case_id: str
    description: str
    category: BenchmarkCategory = field(metadata={"toml_input": False})
    case_path: str = field(metadata={"toml_input": False})
    files: tuple[BenchmarkFile, ...]
    entries: tuple[BenchmarkEntry, ...]

    @property
    def file_contents(self) -> dict[str, str]:
        return {source_file.path: source_file.content for source_file in self.files}
