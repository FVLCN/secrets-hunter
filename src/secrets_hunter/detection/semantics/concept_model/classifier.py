from secrets_hunter.detection.semantics.classification import ConceptScores
from secrets_hunter.detection.semantics.observation.models import SemanticObservation

from .features import concept_feature_names
from .log_odds import SemanticConceptScorer


class LogOddsConceptClassifier:
    def __init__(self, scorer: SemanticConceptScorer) -> None:
        self.scorer = scorer

    def classify(self, observation: SemanticObservation) -> ConceptScores:
        return ConceptScores(
            self.scorer.score_probabilities(concept_feature_names(observation))
        )
