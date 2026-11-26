from dataclasses import dataclass

from secrets_hunter.detection.entropy_classification import (
    EntropyClassification,
    EntropyFamilySpec
)
from secrets_hunter.detection.entropy_metrics import calculate_shannon_entropy
from secrets_hunter.detection.hash_classification import (
    HashValueClassification,
    classify_hash_value
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
    entropy_spec: EntropyFamilySpec | None = None


class ValueAnalyzer:
    def __init__(self, value_classifier: ValueClassifier) -> None:
        self.value_classifier = value_classifier

    def analyze(
        self,
        value: str,
        entropy_classification: EntropyClassification | None = None
    ) -> ValueAnalysis:
        normalized_value = value or ""

        if entropy_classification is not None:
            classification = entropy_classification.value_classification
            entropy = entropy_classification.entropy
            entropy_spec = entropy_classification.spec
        else:
            classification = self.value_classifier.classify(normalized_value)
            entropy = calculate_shannon_entropy(normalized_value)
            entropy_spec = None

        return ValueAnalysis(
            value=normalized_value,
            classification=classification,
            entropy=entropy,
            hash_classification=classify_hash_value(normalized_value),
            entropy_spec=entropy_spec
        )
