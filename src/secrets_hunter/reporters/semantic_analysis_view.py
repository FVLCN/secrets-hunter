from dataclasses import dataclass
from typing import Self, TypedDict

from secrets_hunter.models.fact import Fact
from secrets_hunter.models.semantic_analysis import (
    DecisionGate,
    SemanticAnalysisResult,
    SemanticConceptResult,
    SemanticProviderMatchResult,
)
from secrets_hunter.reporters.matched_evidence_view import (
    MatchedEvidenceView,
    concept_display_name,
    source_display_name,
)


class SemanticConceptPresentation(TypedDict):
    percent: int
    filled_cells: int
    total_cells: int
    threshold_hit: bool | None
    text: str


@dataclass(frozen=True)
class SemanticConceptView:
    display_name: str
    concept_id: str
    probability: float | None
    evidence: tuple[MatchedEvidenceView, ...]
    origin: str
    strength: str
    decision_gate: DecisionGate | None

    @property
    def threshold_hit(self) -> bool | None:
        if self.decision_gate is None:
            return None
        return self.decision_gate.is_met(self.probability)

    @property
    def presentation(self) -> SemanticConceptPresentation | None:
        if self.origin != "model":
            return None

        probability = self.probability or 0.0
        total_cells = 10
        percent = round(probability * 100)
        filled_cells = min(total_cells, max(0, round(probability * total_cells)))
        bar = "▇" * filled_cells + "·" * (total_cells - filled_cells)
        return SemanticConceptPresentation(
            percent=percent,
            filled_cells=filled_cells,
            total_cells=total_cells,
            threshold_hit=self.threshold_hit,
            text=f"[{bar}] {percent}%",
        )

    @classmethod
    def from_result(
        cls,
        concept: SemanticConceptResult,
    ) -> Self:
        display_name = concept.display_name or concept_display_name(concept.concept_id)
        return cls(
            display_name=display_name,
            concept_id=concept.concept_id,
            probability=concept.probability,
            origin=concept.origin,
            strength=concept.strength,
            decision_gate=concept.decision_gate,
            evidence=tuple(
                MatchedEvidenceView.from_result(
                    keyword,
                    concept_label=display_name,
                )
                for keyword in concept.strongest_keywords
            )
        )


@dataclass(frozen=True)
class SemanticProviderView:
    id: str
    name: str
    kind: str
    target_concept_id: str
    evidence: tuple[MatchedEvidenceView, ...]
    matched_pattern_id: str | None = None
    classification: str | None = None

    @property
    def public(self) -> bool:
        return self.classification == "public_credential"

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
            evidence=tuple(
                MatchedEvidenceView.from_result(
                    keyword,
                    concept_label=concept_display_name(provider.target_concept_id),
                )
                for keyword in provider.strongest_keywords
            ),
            matched_pattern_id=provider.matched_pattern_id,
            classification=provider.classification,
        )


@dataclass(frozen=True)
class MatchedSignalView:
    concept_id: str
    display_name: str
    strength: str
    source: str
    evidence: str
    text: str
    provider_id: str | None = None
    provider_name: str | None = None
    provider_kind: str | None = None
    matched_pattern_id: str | None = None

    def to_dict(self) -> dict[str, object]:
        data: dict[str, object] = {
            "concept_id": self.concept_id,
            "display_name": self.display_name,
            "strength": self.strength,
            "source": self.source,
            "evidence": self.evidence,
            "text": self.text,
        }
        if self.provider_id is not None:
            data["provider_id"] = self.provider_id
            data["provider_name"] = self.provider_name
            data["provider_kind"] = self.provider_kind
        if self.matched_pattern_id is not None:
            data["matched_pattern_id"] = self.matched_pattern_id
        return data


@dataclass(frozen=True)
class ModelSignalView:
    concept_id: str
    display_name: str
    probability: float | None
    decision_gate: DecisionGate | None
    text: str

    @property
    def threshold_hit(self) -> bool | None:
        if self.decision_gate is None:
            return None
        return self.decision_gate.is_met(self.probability)

    def to_dict(self) -> dict[str, object]:
        gate = self.decision_gate
        return {
            "concept_id": self.concept_id,
            "display_name": self.display_name,
            "probability": (
                round(self.probability, 4)
                if self.probability is not None
                else None
            ),
            "decision_gate": gate.label if gate is not None else None,
            "decision_threshold": gate.threshold if gate is not None else None,
            "threshold_hit": self.threshold_hit,
            "secondary_decision_gate": (
                gate.secondary_label if gate is not None else None
            ),
            "secondary_decision_threshold": (
                gate.secondary_threshold if gate is not None else None
            ),
            "text": self.text,
        }


@dataclass(frozen=True)
class SemanticAnalysisView:
    concepts: tuple[SemanticConceptView, ...]
    providers: tuple[SemanticProviderView, ...]
    facts: tuple[Fact, ...]

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
    def matched_signals(self) -> tuple[MatchedSignalView, ...]:
        matched = [
            (concept.concept_id, item)
            for concept in self.concepts
            if concept.origin == "evidence"
            for item in concept.evidence
        ]
        name_width = max((
            len(item.concept_label) for _, item in matched
        ), default=0)
        strength_width = max((
            len(item.strength) for _, item in matched
        ), default=0)
        source_width = max((
            len(source_display_name(item.source)) for _, item in matched
        ), default=0)
        matched_patterns = {
            provider.id: provider.matched_pattern_id
            for provider in self.providers
            if provider.matched_pattern_id is not None
        }
        concept_signals = tuple(
            MatchedSignalView(
                concept_id=concept_id,
                display_name=item.concept_label,
                strength=item.strength,
                source=item.source,
                evidence=item.evidence,
                text=item.format_text(
                    name_width=name_width,
                    strength_width=strength_width,
                    source_width=source_width,
                ),
                provider_id=item.provider_id,
                provider_name=item.provider_name,
                provider_kind=item.provider_kind,
                matched_pattern_id=(
                    matched_patterns.get(item.provider_id)
                    if item.source == "provider_pattern" and item.provider_id is not None
                    else None
                ),
            )
            for concept_id, item in matched
        )
        return tuple(concept_signals)

    @property
    def model_signals(self) -> tuple[ModelSignalView, ...]:
        model_concepts = [
            concept
            for concept in self.concepts
            if concept.origin == "model"
        ]
        name_width = max((len(concept.display_name) for concept in model_concepts), default=0)
        signals: list[ModelSignalView] = []
        for concept in model_concepts:
            presentation = concept.presentation
            text = (
                presentation["text"]
                if presentation is not None
                else f"[{concept.strength}]"
            )
            signals.append(ModelSignalView(
                concept_id=concept.concept_id,
                display_name=concept.display_name,
                probability=concept.probability,
                decision_gate=concept.decision_gate,
                text=f"{concept.display_name.ljust(name_width)} {text}",
            ))
        return tuple(signals)

    def to_dict(self) -> dict[str, object]:
        return {
            "matched_signals": [signal.to_dict() for signal in self.matched_signals],
            "model_signals": [signal.to_dict() for signal in self.model_signals],
            "facts": [fact.to_dict() for fact in self.facts],
        }
