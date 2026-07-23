from dataclasses import dataclass
from enum import StrEnum


class LexicalKind(StrEnum):
    ENGLISH_TEXT = "english_text"
    RANDOM = "random"


@dataclass(frozen=True)
class LexicalAnalysis:
    string: str
    corpus_tokens: tuple[str, ...]
    kind: LexicalKind

    @property
    def is_english_text(self) -> bool:
        return self.kind is LexicalKind.ENGLISH_TEXT
