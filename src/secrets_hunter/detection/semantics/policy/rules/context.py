from dataclasses import dataclass
from typing import Self

from secrets_hunter.detection.semantics.catalog import ConceptId, SemanticPolicyConfig
from secrets_hunter.detection.semantics.observation import FactId, SemanticObservation

from ..concept_groups import PolicyConceptGroups


@dataclass(frozen=True)
class DecisionContext:
    observation: SemanticObservation
    groups: PolicyConceptGroups

    @classmethod
    def build(
        cls,
        observation: SemanticObservation,
        groups: PolicyConceptGroups,
    ) -> Self:
        return cls(observation=observation, groups=groups)

    @property
    def policy(self) -> SemanticPolicyConfig:
        return self.groups.policy

    def has_fact(self, fact: FactId) -> bool:
        return self.observation.has_fact(fact)

    def has_name_token(self, token: str) -> bool:
        return token.casefold() in self.observation.name_tokens

    @property
    def has_credential_context(self) -> bool:
        return (
            not self.has_fact(FactId.TERMINAL_IDENTIFIER_SUFFIX)
            and self.groups.active(
                self.groups.credentials, self.policy.decision_thresholds.credential
            )
        )

    @property
    def has_strong_direct_credential_evidence(self) -> bool:
        return (
            not self.has_fact(FactId.TERMINAL_IDENTIFIER_SUFFIX)
            and self.groups.matched(self.groups.credentials)
        )

    @property
    def has_strong_inferred_credential(self) -> bool:
        probability = self.groups.inferred_probability(self.groups.credentials)
        return (
            not self.has_fact(FactId.TERMINAL_IDENTIFIER_SUFFIX)
            and probability > 0
            and probability >= self.policy.decision_thresholds.strong_credential
        )

    @property
    def has_target_context(self) -> bool:
        return self.groups.active(
            self.groups.targets, self.policy.decision_thresholds.target
        )

    @property
    def has_artifact_context(self) -> bool:
        other_artifacts = tuple(
            concept_id for concept_id in self.groups.artifacts
            if concept_id is not ConceptId.PUBLIC_CRYPTO_ARTIFACT
        )
        return (
            self.groups.matched((ConceptId.PUBLIC_CRYPTO_ARTIFACT,))
            or self.groups.active(
                other_artifacts, self.policy.decision_thresholds.reject
            )
        )

    @property
    def has_value_rejection_context(self) -> bool:
        return self.groups.active(
            self.groups.value_rejections, self.policy.decision_thresholds.reject
        )

    @property
    def has_identifier_context(self) -> bool:
        return self.groups.active(
            self.groups.identifiers, self.policy.decision_thresholds.context_reject
        )

    @property
    def has_explicit_identifier_context(self) -> bool:
        return self.groups.matched(self.groups.identifiers)

    @property
    def has_fixture_context(self) -> bool:
        return self.groups.active(
            (ConceptId.TEST_FIXTURE,), self.policy.decision_thresholds.reject
        )

    @property
    def has_neutral_context(self) -> bool:
        return self.groups.active(
            self.groups.neutral, self.policy.decision_thresholds.neutral
        )

    @property
    def has_ordinary_context(self) -> bool:
        return (
            self.groups.matched(self.groups.ordinary, strong_only=False)
            or self.groups.active(
                self.groups.ordinary, self.policy.decision_thresholds.neutral_reject
            )
        )

    @property
    def has_reference_context(self) -> bool:
        return self.groups.active(
            (ConceptId.VERSION_OR_REFERENCE_ARTIFACT,),
            self.policy.decision_thresholds.reject,
        )

    @property
    def has_role_conflict(self) -> bool:
        return (
            self.has_credential_context
            and (self.has_artifact_context or self.has_identifier_context)
        )

    @property
    def strong_secret_context(self) -> bool:
        return (
            self.has_strong_direct_credential_evidence
            and self.has_target_context
            and not self.has_role_conflict
        )

    @property
    def has_secret_classification(self) -> bool:
        return self.has_credential_context or self.has_target_context
