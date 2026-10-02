from dataclasses import dataclass

from secrets_hunter.detection.entropy_classification import EntropyClassification
from secrets_hunter.detection.entropy_metrics import calculate_shannon_entropy
from secrets_hunter.detection.hash_classification import (
    HashValueClassification,
    classify_hash_value,
    strip_hash_prefix
)
from secrets_hunter.detection.value_classification import (
    ValueClassification,
    ValueClassifier
)


@dataclass(frozen=True)
class ValueAnalysis:
    value: str
    classification: ValueClassification
    entropy: float
    hash_classification: HashValueClassification | None


class ValueAnalyzer:
    def __init__(self, value_classifier: ValueClassifier) -> None:
        self.value_classifier = value_classifier

    def analyze(
        self,
        value: str,
        entropy_classification: EntropyClassification | None = None
    ) -> ValueAnalysis:
        normalized_value = value or ""
        entropy_value = strip_hash_prefix(normalized_value)
        can_reuse_entropy = (
            entropy_classification is not None
            and entropy_value == normalized_value
        )

        classification = (
            entropy_classification.value_classification
            if can_reuse_entropy and entropy_classification is not None
            else self.value_classifier.classify(normalized_value)
        )
        entropy = (
            entropy_classification.entropy
            if can_reuse_entropy and entropy_classification is not None
            else calculate_shannon_entropy(normalized_value)
        )

        return ValueAnalysis(
            value=normalized_value,
            classification=classification,
            entropy=entropy,
            hash_classification=classify_hash_value(normalized_value)
        )
