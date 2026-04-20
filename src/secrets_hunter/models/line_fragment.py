from abc import ABC
from dataclasses import dataclass


@dataclass(frozen=True)
class SourceFragment:
    # Raw source block yielded by the reader.
    content: str
    start_line: int
    end_line: int


@dataclass(frozen=True)
class LineFragment(ABC):
    # Extracted candidate derived from a SourceFragment.
    content: str

    @property
    def special_finding_type(self) -> str | None:
        return None


@dataclass(frozen=True)
class GenericStringFragment(LineFragment):
    pass


@dataclass(frozen=True)
class DBConnectionFragment(LineFragment):
    @property
    def special_finding_type(self) -> str | None:
        return "DB Connection String"


@dataclass(frozen=True)
class PEMKeyFragment(LineFragment):
    # Parsed PEM structure kept with the raw matched content.
    header: str | None
    body: str | None
    footer: str | None
    inline: bool = False

    @property
    def special_finding_type(self) -> str | None:
        return "PEM Key"
