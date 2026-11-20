from collections.abc import Mapping
from dataclasses import dataclass
from typing import Self

from secrets_hunter.detection.semantics.catalog import (
    ConceptId,
    EvidenceStrength,
    SemanticPolicyConfig,
)
from secrets_hunter.detection.semantics.classification import ConceptScores
from secrets_hunter.immutability import frozen_mapping

from .indexes import PolicyIndexes
from .models import ConceptKeywordEvidence, ResolvedConcept


@dataclass(frozen=True)
class PolicyConceptGroups:
    concepts: Mapping[ConceptId, ResolvedConcept]
    inferred_probabilities: Mapping[ConceptId, float]
    policy: SemanticPolicyConfig
    credentials: tuple[ConceptId, ...]
    targets: tuple[ConceptId, ...]
    artifacts: tuple[ConceptId, ...]
    value_rejections: tuple[ConceptId, ...]
    identifiers: tuple[ConceptId, ...]
    neutral: tuple[ConceptId, ...]
    ordinary: tuple[ConceptId, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "concepts", frozen_mapping(self.concepts))
        object.__setattr__(
            self, "inferred_probabilities", frozen_mapping(self.inferred_probabilities)
        )

    @classmethod
    def resolve(
        cls,
        concept_scores: ConceptScores,
        evidence_by_concept: Mapping[ConceptId, tuple[ConceptKeywordEvidence, ...]],
        indexes: PolicyIndexes,
        policy: SemanticPolicyConfig,
    ) -> Self:
        unknown = (
            set(concept_scores.probabilities) | set(evidence_by_concept)
        ) - set(indexes.concepts_by_id)
        if unknown:
            raise ValueError(
                "Semantic signals reference concepts outside the active catalog: "
                + ", ".join(sorted(unknown))
            )

        credentials = indexes.credentials
        targets = indexes.targets
        artifacts = indexes.artifacts
        value_rejections = indexes.value_rejections
        identifiers = indexes.identifiers
        neutral = indexes.neutral
        ordinary = indexes.ordinary
        concepts: dict[ConceptId, ResolvedConcept] = {}
        for concept_id, evidence in evidence_by_concept.items():
            if evidence:
                concepts[concept_id] = ResolvedConcept(
                    concept_id=concept_id,
                    origin="evidence",
                    strength=(
                        EvidenceStrength.STRONG
                        if any(e.strength is EvidenceStrength.STRONG for e in evidence)
                        else EvidenceStrength.WEAK
                    ),
                    strongest_keywords=evidence,
                )

        strong_matches = {
            concept_id for concept_id, signal in concepts.items()
            if signal.strength is EvidenceStrength.STRONG
        }
        blocked_inferences: set[ConceptId] = set()
        if strong_matches.intersection(credentials):
            blocked_inferences.update(artifacts + identifiers + neutral + ordinary)
            blocked_inferences.update(credentials)
            blocked_inferences.add(ConceptId.TEST_FIXTURE)
        if strong_matches.intersection(artifacts + identifiers):
            blocked_inferences.update(credentials + targets + artifacts + identifiers)

        inferred_probabilities = {
            concept_id: probability
            for concept_id, probability in concept_scores.probabilities.items()
            if concept_id not in blocked_inferences
            and concept_id not in strong_matches
            and probability > 0
        }
        for concept_id, probability in inferred_probabilities.items():
            if concept_id not in concepts:
                concepts[concept_id] = ResolvedConcept(
                    concept_id=concept_id,
                    origin="model",
                    strength=EvidenceStrength.WEAK,
                    strongest_keywords=(),
                    probability=probability,
                )

        return cls(
            concepts=concepts,
            inferred_probabilities=inferred_probabilities,
            policy=policy,
            credentials=credentials,
            targets=targets,
            artifacts=artifacts,
            value_rejections=value_rejections,
            identifiers=identifiers,
            neutral=neutral,
            ordinary=ordinary,
        )

    def matched(
        self,
        concept_ids: tuple[ConceptId, ...],
        *,
        strong_only: bool = True,
    ) -> bool:
        return any(
            signal is not None
            and signal.origin == "evidence"
            and (
                not strong_only
                or signal.strength is EvidenceStrength.STRONG
            )
            for concept_id in concept_ids
            for signal in (self.concepts.get(concept_id),)
        )

    def inferred_probability(self, concept_ids: tuple[ConceptId, ...]) -> float:
        return max((
            self.inferred_probabilities.get(concept_id, 0.0)
            for concept_id in concept_ids
        ), default=0.0)

    def active(
        self,
        concept_ids: tuple[ConceptId, ...],
        threshold: float,
    ) -> bool:
        inferred_probability = self.inferred_probability(concept_ids)
        return (
            self.matched(concept_ids)
            or (inferred_probability > 0 and inferred_probability >= threshold)
        )
