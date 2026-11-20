from collections.abc import Mapping
from dataclasses import dataclass, field

from secrets_hunter.immutability import frozen_mapping


type FactDetail = str | int | float | tuple[str, ...]


@dataclass(frozen=True)
class Fact:
    name: str
    display_name: str
    evidence: str
    source: str | None = None
    details: Mapping[str, FactDetail] = field(default_factory=dict)
    sensitive: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "details", frozen_mapping(self.details))

    @property
    def text(self) -> str:
        if not self.evidence:
            return self.display_name
        return f"{self.display_name} ({self.evidence})"

    def to_dict(self) -> dict[str, object]:
        data: dict[str, object] = {
            "name": self.name,
            "display_name": self.display_name,
            "evidence": self.evidence,
            "text": self.text,
        }
        if self.source is not None:
            data["source"] = self.source
        if self.details:
            data["details"] = dict(self.details)
        return data
