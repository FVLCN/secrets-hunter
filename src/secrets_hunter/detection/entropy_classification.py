from collections.abc import Mapping
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
class EntropyFamilySpec:
    threshold: float
    finding_kind: FindingKind


@dataclass(frozen=True)
class EntropyClassification:
    value_classification: ValueClassification
    entropy: float
    spec: EntropyFamilySpec


class EntropyClassifier:
    def __init__(
        self,
        value_classifier: ValueClassifier,
        *,
        hex_threshold: float,
        b64_threshold: float
    ) -> None:
        self.value_classifier = value_classifier
        self.family_specs: Mapping[EntropyFamily, EntropyFamilySpec] = {
            EntropyFamily.HEX: EntropyFamilySpec(
                threshold=hex_threshold,
                finding_kind=HIGH_ENTROPY_HEX_KIND
            ),
            EntropyFamily.BASE64: EntropyFamilySpec(
                threshold=b64_threshold,
                finding_kind=HIGH_ENTROPY_BASE64_KIND
            )
        }

    def classify(self, value: str) -> EntropyClassification | None:
        cleaned = strip_hash_prefix(value)
        value_classification = self.value_classifier.classify(cleaned)
        entropy_family = value_classification.entropy_family

        if entropy_family is None:
            return None

        spec = self.family_specs[entropy_family]

        if max_possible_entropy(cleaned) < spec.threshold:
            return None

        entropy = calculate_shannon_entropy(cleaned)

        if entropy < spec.threshold:
            return None

        return EntropyClassification(
            value_classification=value_classification,
            entropy=entropy,
            spec=spec
        )

    def is_high_entropy(self, value: str) -> bool:
        return self.classify(value) is not None
