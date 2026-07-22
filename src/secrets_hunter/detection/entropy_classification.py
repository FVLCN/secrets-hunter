from dataclasses import dataclass

from secrets_hunter.detection.entropy_metrics import (
    calculate_shannon_entropy,
    max_possible_entropy
)
from secrets_hunter.detection.finding_kinds import (
    HIGH_ENTROPY_BASE64_KIND,
    HIGH_ENTROPY_HEX_KIND
)
from secrets_hunter.detection.hash_classification import strip_hash_prefix
from secrets_hunter.detection.value_classification import (
    EntropyFamily,
    ValueClassification,
    ValueClassifier
)
from secrets_hunter.models import FindingKind


@dataclass(frozen=True)
class EntropyClassification:
    value_classification: ValueClassification
    entropy: float
    finding_kind: FindingKind


class EntropyClassifier:
    def __init__(
        self,
        value_classifier: ValueClassifier,
        *,
        hex_threshold: float,
        b64_threshold: float
    ) -> None:
        self.value_classifier = value_classifier
        self.hex_threshold = hex_threshold
        self.b64_threshold = b64_threshold

    def classify(self, value: str) -> EntropyClassification | None:
        cleaned = strip_hash_prefix(value)
        value_classification = self.value_classifier.classify(cleaned)
        entropy_family = value_classification.entropy_family

        if entropy_family is None:
            return None

        if entropy_family is EntropyFamily.HEX:
            threshold = self.hex_threshold
            finding_kind = HIGH_ENTROPY_HEX_KIND
        else:
            threshold = self.b64_threshold
            finding_kind = HIGH_ENTROPY_BASE64_KIND

        if max_possible_entropy(cleaned) < threshold:
            return None

        entropy = calculate_shannon_entropy(cleaned)

        if entropy < threshold:
            return None

        return EntropyClassification(
            value_classification=value_classification,
            entropy=entropy,
            finding_kind=finding_kind
        )

    def is_high_entropy(self, value: str) -> bool:
        return self.classify(value) is not None
