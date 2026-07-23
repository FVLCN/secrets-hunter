from dataclasses import dataclass
from typing import override

from secrets_hunter.detection.finding_kinds import (
    DB_CONNECTION_KIND,
    PEM_KEY_KIND
)
from secrets_hunter.detection.pem import PemAnalysis
from secrets_hunter.models import FindingKind


@dataclass(frozen=True)
class SourceFragment:
    # Raw source block yielded by the reader.
    content: str
    start_line: int
    end_line: int


@dataclass(frozen=True)
class LineFragment:
    # Extracted candidate derived from a SourceFragment.
    content: str

    @property
    def special_finding_kind(self) -> FindingKind | None:
        return None


@dataclass(frozen=True)
class GenericStringFragment(LineFragment):
    pass


@dataclass(frozen=True)
class DBConnectionFragment(LineFragment):
    @property
    @override
    def special_finding_kind(self) -> FindingKind | None:
        return DB_CONNECTION_KIND


@dataclass(frozen=True)
class PEMKeyFragment(LineFragment):
    # Parsed PEM structure kept with the raw matched content.
    body: str | None
    footer: str | None
    pem_analysis: PemAnalysis

    @property
    @override
    def special_finding_kind(self) -> FindingKind | None:
        return PEM_KEY_KIND
