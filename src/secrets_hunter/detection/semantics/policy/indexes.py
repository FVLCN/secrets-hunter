from collections.abc import Mapping
from dataclasses import dataclass
from typing import Self

from secrets_hunter.detection.semantics.catalog import (
    ConceptId,
    SemanticCatalog,
    SemanticConcept,
)
from secrets_hunter.immutability import frozen_mapping


@dataclass(frozen=True)
class PolicyIndexes:
    concepts_by_id: Mapping[ConceptId, SemanticConcept]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "concepts_by_id",
            frozen_mapping(self.concepts_by_id)
        )

    @classmethod
    def from_catalog(cls, catalog: SemanticCatalog) -> Self:
        return cls(
            concepts_by_id={concept.id: concept for concept in catalog.concepts},
        )
