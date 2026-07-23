from dataclasses import dataclass
from typing import Self

from secrets_hunter.models.semantic_analysis import (
    SemanticAnalysisResult,
    SemanticConceptResult,
    SemanticKeywordEvidenceResult,
    SemanticProviderMatchResult,
)


@dataclass(frozen=True)
class SemanticKeywordView:
    term: str
    source: str
    display_term: str | None = None
    provider_id: str | None = None
    provider_name: str | None = None
    provider_kind: str | None = None

    @classmethod
    def from_result(
        cls,
        evidence: SemanticKeywordEvidenceResult,
    ) -> Self:
        return cls(
            term=evidence.term,
            source=evidence.source,
            display_term=evidence.display_term,
            provider_id=evidence.provider_id,
            provider_name=evidence.provider_name,
            provider_kind=evidence.provider_kind,
        )

    def to_dict(self) -> dict[str, object]:
        data: dict[str, object] = {
            "term": self.term,
            "source": self.source,
        }

        if self.display_term:
            data["display_term"] = self.display_term

        if self.provider_id is not None:
            data["provider_id"] = self.provider_id
            data["provider_name"] = self.provider_name
            data["provider_kind"] = self.provider_kind

        return data


@dataclass(frozen=True)
class SemanticConceptView:
    name: str
    concept_id: str
    probability: float
    kind: str
    strongest_keywords: tuple[SemanticKeywordView, ...]

    @classmethod
    def from_result(
        cls,
        concept: SemanticConceptResult,
    ) -> Self:
        return cls(
            name=concept.display_name or concept.name,
            concept_id=concept.name,
            probability=concept.probability,
            kind=concept.kind,
            strongest_keywords=tuple(
                SemanticKeywordView.from_result(keyword)
                for keyword in concept.strongest_keywords
            ),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "concept_id": self.concept_id,
            "probability": round(self.probability, 4),
            "kind": self.kind,
            "strongest_keywords": [
                keyword.to_dict()
                for keyword in self.strongest_keywords
            ],
        }


@dataclass(frozen=True)
class SemanticProviderView:
    id: str
    name: str
    kind: str
    target_concept: str
    strongest_keywords: tuple[SemanticKeywordView, ...]
    matched_pattern_id: str | None = None

    @classmethod
    def from_result(
        cls,
        provider: SemanticProviderMatchResult,
    ) -> Self:
        return cls(
            id=provider.id,
            name=provider.name,
            kind=provider.kind,
            target_concept=provider.target_concept,
            strongest_keywords=tuple(
                SemanticKeywordView.from_result(keyword)
                for keyword in provider.strongest_keywords
            ),
            matched_pattern_id=provider.matched_pattern_id,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "name": self.name,
            "kind": self.kind,
            "target_concept": self.target_concept,
            "strongest_keywords": [
                keyword.to_dict()
                for keyword in self.strongest_keywords
            ],
        }


@dataclass(frozen=True)
class SemanticAnalysisView:
    concepts: tuple[SemanticConceptView, ...]
    providers: tuple[SemanticProviderView, ...]
    facts: tuple[str, ...]

    @classmethod
    def from_result(
        cls,
        analysis: SemanticAnalysisResult,
    ) -> Self:
        return cls(
            concepts=tuple(
                SemanticConceptView.from_result(concept)
                for concept in analysis.concepts
            ),
            providers=tuple(
                SemanticProviderView.from_result(provider)
                for provider in analysis.providers
            ),
            facts=analysis.facts,
        )

    @property
    def pattern_provider_match(self) -> SemanticProviderView | None:
        return next(
            (
                provider
                for provider in self.providers
                if provider.matched_pattern_id is not None
            ),
            None,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "concepts": [
                concept.to_dict()
                for concept in self.concepts
            ],
            "providers": [
                provider.to_dict()
                for provider in self.providers
            ],
            "facts": list(self.facts),
        }
