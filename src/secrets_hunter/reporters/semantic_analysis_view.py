from dataclasses import dataclass
from typing import Self, TypedDict

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
    strength: str = "strong"
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
            strength=evidence.strength,
            display_term=evidence.display_term,
            provider_id=evidence.provider_id,
            provider_name=evidence.provider_name,
            provider_kind=evidence.provider_kind,
        )

    def to_dict(self) -> dict[str, object]:
        data: dict[str, object] = {
            "term": self.term,
            "source": self.source,
            "strength": self.strength,
        }

        if self.display_term:
            data["display_term"] = self.display_term

        if self.provider_id is not None:
            data["provider_id"] = self.provider_id
            data["provider_name"] = self.provider_name
            data["provider_kind"] = self.provider_kind

        return data


class SemanticKeywordProvider(TypedDict):
    id: str
    name: str


class SemanticKeywordGroup(TypedDict):
    source: str
    label: str
    terms: list[str]
    providers: list[SemanticKeywordProvider]


class SemanticConceptPresentation(TypedDict):
    percent: int
    filled_cells: int
    total_cells: int
    text: str


@dataclass(frozen=True)
class SemanticConceptView:
    display_name: str
    concept_id: str
    probability: float | None
    strongest_keywords: tuple[SemanticKeywordView, ...]
    origin: str
    strength: str

    @property
    def keyword_groups(self) -> list[SemanticKeywordGroup]:
        groups_by_source: dict[str, SemanticKeywordGroup] = {}
        for keyword in self.strongest_keywords:
            term = keyword.term
            if not term:
                continue

            source = keyword.source
            group = groups_by_source.setdefault(source, {
                "source": source,
                "label": "name" if source == "var_name" else source.replace("_", " "),
                "terms": [],
                "providers": [],
            })
            if term not in group["terms"]:
                group["terms"].append(term)

            if keyword.provider_id is not None:
                provider: SemanticKeywordProvider = {
                    "id": keyword.provider_id,
                    "name": keyword.provider_name or keyword.provider_id,
                }
                if provider not in group["providers"]:
                    group["providers"].append(provider)

        return list(groups_by_source.values())

    @property
    def presentation(self) -> SemanticConceptPresentation | None:
        if self.origin != "model":
            return None

        probability = self.probability or 0.0
        total_cells = 10
        percent = round(probability * 100)
        filled_cells = min(total_cells, max(0, round(probability * total_cells)))
        bar = "▇" * filled_cells + "·" * (total_cells - filled_cells)
        return {
            "percent": percent,
            "filled_cells": filled_cells,
            "total_cells": total_cells,
            "text": f"[{bar}] {percent}%",
        }

    @classmethod
    def from_result(
        cls,
        concept: SemanticConceptResult,
    ) -> Self:
        return cls(
            display_name=concept.display_name or concept.concept_id,
            concept_id=concept.concept_id,
            probability=concept.probability,
            origin=concept.origin,
            strength=concept.strength,
            strongest_keywords=tuple(
                SemanticKeywordView.from_result(keyword)
                for keyword in concept.strongest_keywords
            )
        )

    def to_dict(self) -> dict[str, object]:
        data: dict[str, object] = {
            "display_name": self.display_name,
            "concept_id": self.concept_id,
            "probability": (
                round(self.probability, 4) if self.probability is not None else None
            ),
            "origin": self.origin,
            "strength": self.strength,
            "keyword_groups": self.keyword_groups,
            "strongest_keywords": [
                keyword.to_dict()
                for keyword in self.strongest_keywords
            ]
        }

        presentation = self.presentation
        if presentation is not None:
            data["presentation"] = presentation

        return data


@dataclass(frozen=True)
class SemanticProviderView:
    id: str
    name: str
    kind: str
    target_concept_id: str
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
            target_concept_id=provider.target_concept_id,
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
            "target_concept_id": self.target_concept_id,
            "matched_pattern_id": self.matched_pattern_id,
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
    hash_algorithm: str | None = None
    value_entropy: float | None = None

    @property
    def fact_details(self) -> dict[str, dict[str, str | float]]:
        details: dict[str, dict[str, str | float]] = {}
        if "hash_shaped_value" in self.facts and self.hash_algorithm is not None:
            details["hash_shaped_value"] = {"algorithm": self.hash_algorithm}
        if "high_entropy" in self.facts and self.value_entropy is not None:
            details["high_entropy"] = {"bits_per_character": self.value_entropy}
        return details

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
            hash_algorithm=analysis.hash_algorithm,
            value_entropy=analysis.value_entropy,
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
            "fact_details": self.fact_details,
        }
