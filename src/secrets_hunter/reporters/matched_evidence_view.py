from dataclasses import dataclass, replace
from typing import Self

from secrets_hunter.models.semantic_analysis import SemanticKeywordEvidenceResult


_NAME_ROLE_LABELS = {
    "exact_identifier_name": 'exactly "id"',
    "terminal_identifier_suffix": 'ends with "id"',
}


def concept_display_name(concept_id: str) -> str:
    return concept_id.replace("_", " ").capitalize()


def source_display_name(source: str) -> str:
    return {
        "var_name": "Name",
        "name_role": "Name",
        "value_english_words": "Value",
    }.get(source, source.replace("_", " ").capitalize())


@dataclass(frozen=True)
class MatchedEvidenceView:
    concept_label: str
    term: str
    source: str
    strength: str = "strong"
    display_term: str | None = None
    provider_id: str | None = None
    provider_name: str | None = None
    provider_kind: str | None = None

    @property
    def evidence(self) -> str:
        if self.provider_id is not None:
            provider = self.provider_name or self.provider_id
            if self.source == "provider_pattern":
                return provider
            return f"{self.term}; provider: {provider}"

        if self.source == "name_role":
            return _NAME_ROLE_LABELS.get(
                self.term,
                self.display_term or self.term,
            )

        return self.display_term or self.term

    @property
    def sensitive(self) -> bool:
        return self.source == "value_english_words"

    def masked(self, masked_value: str) -> Self:
        if not self.sensitive:
            return self
        return replace(
            self,
            term=masked_value,
            display_term=masked_value,
        )

    @classmethod
    def from_result(
        cls,
        evidence: SemanticKeywordEvidenceResult,
        *,
        concept_label: str,
    ) -> Self:
        return cls(
            concept_label=concept_label,
            term=evidence.term,
            source=evidence.source,
            strength=evidence.strength,
            display_term=evidence.display_term,
            provider_id=evidence.provider_id,
            provider_name=evidence.provider_name,
            provider_kind=evidence.provider_kind,
        )

    def format_text(
        self,
        *,
        name_width: int = 0,
        strength_width: int = 0,
        source_width: int = 0,
    ) -> str:
        source_label = source_display_name(self.source).ljust(source_width)
        strength_label = f"[{self.strength}]".ljust(strength_width + 2)
        return (
            f"{self.concept_label.ljust(name_width)} "
            f"{strength_label} · {source_label} — {self.evidence}"
        )
