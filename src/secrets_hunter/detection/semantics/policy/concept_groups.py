from collections.abc import Mapping
from dataclasses import dataclass
from typing import Self

from secrets_hunter.detection.semantics.catalog import (
    ConceptId,
    EvidenceStrength,
    SemanticPolicyConfig,
)
from secrets_hunter.detection.semantics.classification import ConceptScores
from secrets_hunter.detection.semantics.evidence_sources import EvidenceSource
from secrets_hunter.immutability import frozen_mapping
from secrets_hunter.models.semantic_analysis import DecisionGate

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

    def matched_from_source(
        self,
        concept_ids: tuple[ConceptId, ...],
        *,
        source: EvidenceSource,
        strong_only: bool = True,
    ) -> bool:
        return any(
            signal is not None
            and signal.origin == "evidence"
            and any(
                evidence.source is source
                and (
                    not strong_only
                    or evidence.strength is EvidenceStrength.STRONG
                )
                for evidence in signal.strongest_keywords
            )
            for concept_id in concept_ids
            for signal in (self.concepts.get(concept_id),)
        )

    def has_weak_only_name_credential_evidence(self) -> bool:
        name_evidence = tuple(
            evidence
            for concept_id in self.credentials
            for concept in (self.concepts.get(concept_id),)
            if concept is not None and concept.origin == "evidence"
            for evidence in concept.strongest_keywords
            if evidence.source is EvidenceSource.VAR_NAME
        )
        return (
            any(
                evidence.strength is EvidenceStrength.WEAK
                for evidence in name_evidence
            )
            and not any(
                evidence.strength is EvidenceStrength.STRONG
                for evidence in name_evidence
            )
        )

    def inferred_probability(self, concept_ids: tuple[ConceptId, ...]) -> float:
        return max((
            self.inferred_probabilities.get(concept_id, 0.0)
            for concept_id in concept_ids
        ), default=0.0)

    def decision_gate(self, concept_id: ConceptId) -> DecisionGate | None:
        thresholds = self.policy.decision_thresholds
        if concept_id in self.credentials:
            return DecisionGate(
                label="credential context",
                threshold=thresholds.credential,
                secondary_label="strong inferred credential",
                secondary_threshold=thresholds.strong_credential,
            )
        if concept_id in self.targets:
            return DecisionGate("target context", thresholds.target)
        if concept_id is ConceptId.PUBLIC_CRYPTO_ARTIFACT:
            # This concept only enters the decision path through direct evidence.
            return None
        if concept_id in self.artifacts or concept_id in self.value_rejections:
            return DecisionGate("reject context", thresholds.reject)
        if concept_id in self.identifiers:
            return DecisionGate("identifier context", thresholds.context_reject)
        if concept_id in self.neutral:
            return DecisionGate("neutral context", thresholds.neutral)
        if concept_id in self.ordinary:
            return DecisionGate("ordinary context", thresholds.neutral_reject)
        if concept_id is ConceptId.TEST_FIXTURE:
            return DecisionGate("fixture context", thresholds.reject)
        return None

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
