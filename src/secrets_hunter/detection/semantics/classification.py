from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol

from secrets_hunter.detection.semantics.catalog.taxonomy import ConceptId
from secrets_hunter.detection.semantics.observation.models import SemanticObservation
from secrets_hunter.immutability import frozen_mapping


@dataclass(frozen=True)
class ConceptScores:
    probabilities: Mapping[ConceptId, float]

    def __post_init__(self) -> None:
        normalized: dict[ConceptId, float] = {}

        for concept_id, probability in self.probabilities.items():
            concept = (
                concept_id
                if isinstance(concept_id, ConceptId)
                else ConceptId(concept_id)
            )
            score = float(probability)

            if not 0.0 <= score <= 1.0:
                raise ValueError(
                    f"Concept probability for {concept.value} must be between 0 and 1"
                )

            normalized[concept] = score

        object.__setattr__(
            self,
            "probabilities",
            frozen_mapping(dict(sorted(normalized.items())))
        )

    def probability(self, concept_id: ConceptId) -> float:
        return self.probabilities.get(concept_id, 0.0)


class ConceptClassifier(Protocol):
    def classify(
        self,
        observation: SemanticObservation,
    ) -> ConceptScores:
        ...
