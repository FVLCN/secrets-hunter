from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Self

from secrets_hunter.detection.semantics.catalog import (
    ConceptCategory,
    ConceptId,
    ConceptPolicy,
    SemanticCatalog,
    SemanticConcept,
)
from secrets_hunter.immutability import frozen_mapping


@dataclass(frozen=True)
class PolicyIndexes:
    concepts_by_id: Mapping[ConceptId, SemanticConcept]
    credentials: tuple[ConceptId, ...] = field(init=False, repr=False)
    targets: tuple[ConceptId, ...] = field(init=False, repr=False)
    artifacts: tuple[ConceptId, ...] = field(init=False, repr=False)
    value_rejections: tuple[ConceptId, ...] = field(init=False, repr=False)
    identifiers: tuple[ConceptId, ...] = field(init=False, repr=False)
    neutral: tuple[ConceptId, ...] = field(init=False, repr=False)
    ordinary: tuple[ConceptId, ...] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "concepts_by_id",
            frozen_mapping(self.concepts_by_id)
        )
        object.__setattr__(self, "credentials", tuple(
            c.id for c in self.concepts_by_id.values()
            if c.category is ConceptCategory.CREDENTIAL
        ))
        object.__setattr__(self, "targets", tuple(
            c.id for c in self.concepts_by_id.values()
            if c.category is ConceptCategory.SECRET_TARGET
        ))
        object.__setattr__(self, "artifacts", tuple(
            c.id for c in self.concepts_by_id.values()
            if c.category is ConceptCategory.NON_SECRET_ARTIFACT
        ))
        object.__setattr__(self, "value_rejections", tuple(
            c.id for c in self.concepts_by_id.values()
            if c.policy is ConceptPolicy.VALUE_REJECT
        ))
        object.__setattr__(self, "identifiers", tuple(
            c.id for c in self.concepts_by_id.values()
            if c.policy is ConceptPolicy.CONTEXT_REJECT_EVIDENCE
        ))
        object.__setattr__(self, "neutral", tuple(
            c.id for c in self.concepts_by_id.values()
            if c.policy is ConceptPolicy.NEUTRAL
        ))
        object.__setattr__(self, "ordinary", tuple(
            c.id for c in self.concepts_by_id.values()
            if c.policy is ConceptPolicy.NEUTRAL_REJECT_EVIDENCE
        ))

    @classmethod
    def from_catalog(cls, catalog: SemanticCatalog) -> Self:
        return cls(
            concepts_by_id={concept.id: concept for concept in catalog.concepts},
        )
