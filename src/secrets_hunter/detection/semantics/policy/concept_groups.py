from collections.abc import Mapping
from dataclasses import dataclass
from typing import Self

from secrets_hunter.detection.semantics.catalog import (
    ConceptCategory,
    ConceptId,
    ConceptPolicy,
    SemanticPolicyConfig,
)
from secrets_hunter.detection.semantics.classification import ConceptScores
from secrets_hunter.immutability import frozen_mapping

from .indexes import PolicyIndexes


@dataclass(frozen=True)
class PolicyConceptGroups:
    probabilities: Mapping[ConceptId, float]
    policy: SemanticPolicyConfig
    credentials: tuple[ConceptId, ...]
    targets: tuple[ConceptId, ...]
    hard_reject_concepts: tuple[ConceptId, ...]
    reject_evidence_concepts: tuple[ConceptId, ...]
    context_reject_concepts: tuple[ConceptId, ...]
    neutral: tuple[ConceptId, ...]
    neutral_reject_concepts: tuple[ConceptId, ...]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "probabilities",
            frozen_mapping(self.probabilities)
        )

    @classmethod
    def classify(
        cls,
        concept_scores: ConceptScores,
        indexes: PolicyIndexes,
        policy: SemanticPolicyConfig
    ) -> Self:
        credentials: list[ConceptId] = []
        targets: list[ConceptId] = []
        hard_reject_concepts: list[ConceptId] = []
        reject_evidence_concepts: list[ConceptId] = []
        context_reject_concepts: list[ConceptId] = []
        neutral: list[ConceptId] = []
        neutral_reject_concepts: list[ConceptId] = []

        probabilities = concept_scores.probabilities
        unknown_concepts = set(probabilities) - set(indexes.concepts_by_id)

        if unknown_concepts:
            raise ValueError(
                "Classifier returned concepts outside the active catalog: "
                + ", ".join(sorted(unknown_concepts))
            )

        for concept_id, probability in probabilities.items():
            if probability <= 0:
                continue

            concept = indexes.concepts_by_id[concept_id]

            if concept.category is ConceptCategory.CREDENTIAL:
                credentials.append(concept_id)

            if concept.category is ConceptCategory.SECRET_TARGET:
                targets.append(concept_id)

            if concept.policy is ConceptPolicy.HARD_REJECT:
                hard_reject_concepts.append(concept_id)
            elif concept.policy in {
                ConceptPolicy.REJECT_EVIDENCE,
                ConceptPolicy.VALUE_REJECT,
            }:
                reject_evidence_concepts.append(concept_id)
            elif concept.policy is ConceptPolicy.CONTEXT_REJECT_EVIDENCE:
                context_reject_concepts.append(concept_id)
            elif concept.policy is ConceptPolicy.NEUTRAL:
                neutral.append(concept_id)
            elif concept.policy is ConceptPolicy.NEUTRAL_REJECT_EVIDENCE:
                neutral_reject_concepts.append(concept_id)

        return cls(
            probabilities=probabilities,
            policy=policy,
            credentials=tuple(credentials),
            targets=tuple(targets),
            hard_reject_concepts=tuple(hard_reject_concepts),
            reject_evidence_concepts=tuple(reject_evidence_concepts),
            context_reject_concepts=tuple(context_reject_concepts),
            neutral=tuple(neutral),
            neutral_reject_concepts=tuple(neutral_reject_concepts),
        )

    def max_probability(self, concept_ids: tuple[ConceptId, ...]) -> float:
        return max(
            (self.probabilities.get(concept_id, 0.0) for concept_id in concept_ids),
            default=0.0
        )

    def above_threshold(
        self,
        concept_ids: tuple[ConceptId, ...],
        threshold: float
    ) -> tuple[ConceptId, ...]:
        return tuple(
            concept_id
            for concept_id in concept_ids
            if self.probabilities.get(concept_id, 0.0) >= threshold
        )

    @property
    def hard_rejects(self) -> tuple[ConceptId, ...]:
        return self.above_threshold(
            self.hard_reject_concepts,
            self.policy.decision_thresholds.reject
        )

    @property
    def reject_evidence(self) -> tuple[ConceptId, ...]:
        return self.above_threshold(
            self.reject_evidence_concepts,
            self.policy.decision_thresholds.reject
        )
