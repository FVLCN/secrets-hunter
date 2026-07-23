from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class FindingKind:
    id: str
    display_name: str = field(compare=False)

    def __str__(self) -> str:
        return self.display_name
