from dataclasses import dataclass
from typing import Self

from secrets_hunter.detection.semantics.catalog import SemanticCatalog
from secrets_hunter.detection.semantics.classification import ConceptClassifier
from secrets_hunter.detection.semantics.concept_model import (
    LogOddsConceptClassifier,
    SemanticConceptScorer,
)
from secrets_hunter.detection.semantics.lexical import LexicalAnalyzer
from secrets_hunter.detection.semantics.observation import (
    SemanticInput,
    SemanticObservationBuilder,
)
from secrets_hunter.detection.semantics.policy import (
    ConceptPolicyResult,
    ConceptSecretPolicy,
)


@dataclass(frozen=True)
class SemanticRuntime:
    _concept_classifier: ConceptClassifier
    _concept_policy: ConceptSecretPolicy
    _observation_builder: SemanticObservationBuilder

    def analyze(self, item: SemanticInput) -> ConceptPolicyResult:
        observation = self._observation_builder.build(item)
        scores = self._concept_classifier.classify(observation)
        return self._concept_policy.evaluate(observation, scores)

    @classmethod
    def from_catalog(
        cls,
        catalog: SemanticCatalog,
        *,
        concept_classifier: ConceptClassifier | None = None,
        lexical_analyzer: LexicalAnalyzer | None = None
    ) -> Self:
        analyzer = lexical_analyzer or LexicalAnalyzer()

        return cls(
            _concept_classifier=(
                concept_classifier
                or LogOddsConceptClassifier(
                    SemanticConceptScorer(
                        expected_concept_ids=catalog.concept_ids
                    )
                )
            ),
            _concept_policy=ConceptSecretPolicy(catalog),
            _observation_builder=SemanticObservationBuilder(catalog, analyzer)
        )
