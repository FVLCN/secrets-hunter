from dataclasses import dataclass
from typing import Self

from secrets_hunter.detection.semantics.catalog import (
    ConceptId,
    SemanticPolicyConfig,
)
from secrets_hunter.detection.semantics.observation import (
    FactId,
    SemanticObservation,
)

from ..concept_groups import PolicyConceptGroups


@dataclass(frozen=True)
class DecisionContext:
    observation: SemanticObservation
    policy: SemanticPolicyConfig
    credential_probability: float
    target_probability: float
    context_reject_probability: float
    neutral_probability: float
    neutral_reject_probability: float
    hard_rejects: tuple[ConceptId, ...]
    reject_evidence: tuple[ConceptId, ...]

    @classmethod
    def build(
        cls,
        observation: SemanticObservation,
        groups: PolicyConceptGroups,
    ) -> Self:
        return cls(
            observation=observation,
            policy=groups.policy,
            credential_probability=groups.max_probability(groups.credentials),
            target_probability=groups.max_probability(groups.targets),
            context_reject_probability=groups.max_probability(
                groups.context_reject_concepts
            ),
            neutral_probability=groups.max_probability(groups.neutral),
            neutral_reject_probability=groups.max_probability(
                groups.neutral_reject_concepts
            ),
            hard_rejects=groups.hard_rejects,
            reject_evidence=groups.reject_evidence,
        )

    def has_fact(self, fact: FactId) -> bool:
        return self.observation.has_fact(fact)

    @property
    def strong_secret_context(self) -> bool:
        thresholds = self.policy.decision_thresholds
        return (
            self.credential_probability >= thresholds.credential
            and self.target_probability >= thresholds.target
        )

    @property
    def has_secret_classification(self) -> bool:
        thresholds = self.policy.decision_thresholds
        return (
            self.credential_probability >= thresholds.credential
            or self.target_probability >= thresholds.target
        )
