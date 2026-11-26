from dataclasses import dataclass

from secrets_hunter.models import RejectionKind


@dataclass(frozen=True)
class RejectionPatternSpec:
    name: str
    pattern: str
    category: str
    flags: tuple[str, ...]
    kind: RejectionKind
