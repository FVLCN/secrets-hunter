import json
import math

from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Self

from secrets_hunter.resources import (
    FrozenJsonObject,
    JsonObject,
    empty_frozen_json_object,
    freeze_json_object,
    load_json_resource,
    normalize_json_object,
    thaw_json_value
)
from secrets_hunter.detection.semantics.catalog.taxonomy import (
    SEMANTIC_ONTOLOGY_VERSION,
    ConceptId,
)
from secrets_hunter.detection.semantics.concept_model.features import (
    SEMANTIC_FEATURE_SCHEMA_VERSION,
)
from secrets_hunter.detection.semantics.concept_model.manifest import ModelManifest
from secrets_hunter.detection.semantics.concept_model.validation import (
    ConceptModelDataValidator
)
from secrets_hunter.immutability import frozen_mapping


MODEL_RESOURCE = "semantics/semantic_concept_model.json"
MODEL_TYPE = "semantic_concept_log_odds_v1"
DEFAULT_CONCEPT_SMOOTHING = 0.1
CONCEPT_FEATURE_SUPPORT_SHRINKAGE = 2.0
MAX_CONCEPT_FEATURE_WEIGHT = 2.0
_NAME_FEATURES = frozenset({
    "name_present",
    "neutral_identifier_present"
})
_NAME_FEATURE_PREFIXES = (
    "name_token=",
    "name_bigram=",
    "name_trigram=",
    "neutral_identifier_token="
)
_PATH_FEATURE_PREFIXES = (
    "file_extension=",
    "path_token="
)
_REJECTION_FEATURES = frozenset({"fact=value_rejected"})
_REJECTION_FEATURE_PREFIXES = (
    "value_rejection_name=",
    "value_rejection_category="
)
_NAME_ONLY_CONCEPTS = frozenset({
    ConceptId.CREDENTIAL_GENERIC,
    ConceptId.KEY_CREDENTIAL,
    ConceptId.ORDINARY_IDENTIFIER_WORDS,
    ConceptId.PASSWORD_CREDENTIAL,
    ConceptId.SECRET_CREDENTIAL,
    ConceptId.TOKEN_CREDENTIAL,
    ConceptId.WEBHOOK_CREDENTIAL
})
_NAME_AND_PATH_CONCEPTS = frozenset({
    ConceptId.CLOUD_PROVIDER_TARGET,
    ConceptId.TEST_FIXTURE,
    ConceptId.VERSION_OR_REFERENCE_ARTIFACT
})


def _is_name_feature(feature: str) -> bool:
    return (
        feature in _NAME_FEATURES
        or feature.startswith(_NAME_FEATURE_PREFIXES)
    )


def _is_path_feature(feature: str) -> bool:
    return feature.startswith(_PATH_FEATURE_PREFIXES)


def _is_rejection_feature(feature: str) -> bool:
    return (
        feature in _REJECTION_FEATURES
        or feature.startswith(_REJECTION_FEATURE_PREFIXES)
    )


def _features_for_concept(
    concept_id: ConceptId,
    features: tuple[str, ...]
) -> set[str]:
    feature_set = set(features)

    if concept_id in _NAME_ONLY_CONCEPTS:
        return {
            feature
            for feature in feature_set
            if _is_name_feature(feature)
        }

    if concept_id in _NAME_AND_PATH_CONCEPTS:
        return {
            feature
            for feature in feature_set
            if _is_name_feature(feature) or _is_path_feature(feature)
        }

    if concept_id is ConceptId.HASH_ARTIFACT:
        return {
            feature
            for feature in feature_set
            if _is_name_feature(feature)
            or _is_path_feature(feature)
            or _is_rejection_feature(feature)
        }

    return feature_set


@dataclass(frozen=True)
class ConceptLogOddsClassifier:
    prior_weight: float
    feature_weights: Mapping[str, float]
    positive_examples: int
    negative_examples: int

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "feature_weights",
            frozen_mapping(self.feature_weights)
        )

    @staticmethod
    def _probability(log_odds: float) -> float:
        if log_odds >= 0:
            return 1 / (1 + math.exp(-log_odds))

        exponential = math.exp(log_odds)
        return exponential / (1 + exponential)

    def score_probability(self, feature_names: tuple[str, ...]) -> float:
        log_odds = self.prior_weight

        for feature in feature_names:
            log_odds += self.feature_weights.get(feature, 0.0)

        return self._probability(log_odds)


@dataclass(frozen=True)
class SemanticConceptLogOddsModel:
    classifiers: Mapping[str, ConceptLogOddsClassifier]
    smoothing: float = DEFAULT_CONCEPT_SMOOTHING
    model_type: str = MODEL_TYPE
    metadata: FrozenJsonObject = field(default_factory=empty_frozen_json_object)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "classifiers",
            frozen_mapping(self.classifiers)
        )
        object.__setattr__(
            self,
            "metadata",
            freeze_json_object(self.metadata, "model.metadata")
        )

    @classmethod
    def from_dict(cls, data: JsonObject) -> Self:
        spec = ConceptModelDataValidator.parse(
            data,
            MODEL_TYPE,
            DEFAULT_CONCEPT_SMOOTHING
        )

        return cls(
            classifiers={
                concept_id: ConceptLogOddsClassifier(
                    prior_weight=classifier.prior_weight,
                    feature_weights=dict(classifier.feature_weights),
                    positive_examples=classifier.positive_examples,
                    negative_examples=classifier.negative_examples
                )
                for concept_id, classifier in spec.classifiers
            },
            smoothing=spec.smoothing,
            model_type=spec.model_type,
            metadata=spec.metadata
        )

    def to_dict(self) -> JsonObject:
        return {
            "model_type": self.model_type,
            "smoothing": self.smoothing,
            "metadata": thaw_json_value(self.metadata),
            "concept_count": len(self.classifiers),
            "concepts": {
                concept_id: {
                    "prior_weight": classifier.prior_weight,
                    "feature_weights": dict(sorted(classifier.feature_weights.items())),
                    "positive_examples": classifier.positive_examples,
                    "negative_examples": classifier.negative_examples,
                    "feature_count": len(classifier.feature_weights)
                }
                for concept_id, classifier in sorted(self.classifiers.items())
            }
        }

    def score_probabilities(self, feature_names: tuple[str, ...]) -> dict[str, float]:
        return {
            concept_id: classifier.score_probability(feature_names)
            for concept_id, classifier in sorted(self.classifiers.items())
        }

class SemanticConceptScorer:
    def __init__(
        self,
        model: SemanticConceptLogOddsModel | JsonObject | None = None,
        model_path: str | Path | None = None,
        *,
        load_packaged_model: bool = True,
        expected_concept_ids: tuple[ConceptId, ...] | None = None
    ) -> None:
        self._expected_concept_ids = expected_concept_ids
        self.model = (
            SemanticConceptLogOddsModel.from_dict(model)
            if isinstance(model, dict)
            else model
        )

        if self.model is None and model_path:
            self.model = self._load_model_path(Path(model_path))

        if self.model is None and load_packaged_model:
            self.model = self._load_packaged_model()

        if self.model is not None:
            self._validate_runtime_compatibility(self.model)

    def _load_model_path(self, model_path: Path) -> SemanticConceptLogOddsModel:
        if not model_path.exists():
            raise FileNotFoundError(f"Semantic concept model not found: {model_path}")

        try:
            raw_data: object = json.loads(model_path.read_text(encoding="utf-8"))
            data = normalize_json_object(raw_data, str(model_path))
            return SemanticConceptLogOddsModel.from_dict(data)
        except Exception as exc:
            raise RuntimeError(
                f"Could not load semantic concept model from {model_path}"
            ) from exc

    def _load_packaged_model(self) -> SemanticConceptLogOddsModel:
        try:
            data = load_json_resource(MODEL_RESOURCE)
            return SemanticConceptLogOddsModel.from_dict(data)
        except Exception as exc:
            raise RuntimeError(
                "Could not load the packaged semantic concept model"
            ) from exc

    def _validate_runtime_compatibility(
        self,
        model: SemanticConceptLogOddsModel
    ) -> None:
        manifest = ModelManifest.from_metadata(model.metadata)

        if manifest.feature_schema_version != SEMANTIC_FEATURE_SCHEMA_VERSION:
            raise ValueError(
                "Semantic concept model feature schema is incompatible: "
                f"expected {SEMANTIC_FEATURE_SCHEMA_VERSION}, "
                f"got {manifest.feature_schema_version!r}. "
                "Regenerate the packaged model for this package build."
            )

        if manifest.ontology_version != SEMANTIC_ONTOLOGY_VERSION:
            raise ValueError(
                "Semantic concept model ontology is incompatible: "
                f"expected {SEMANTIC_ONTOLOGY_VERSION}, "
                f"got {manifest.ontology_version!r}. "
                "Regenerate the packaged model for this package build."
            )

        from .training_data import (
            semantic_model_source_hashes,
            semantic_training_dataset_hash,
        )

        current_dataset_hash = semantic_training_dataset_hash()
        if manifest.dataset_hash != current_dataset_hash:
            raise ValueError(
                "Semantic concept model dataset is stale. "
                "Regenerate the packaged model after changing training examples."
            )

        current_source_hashes = semantic_model_source_hashes()
        if manifest.source_hashes != current_source_hashes:
            raise ValueError(
                "Semantic concept model sources are stale. "
                "Regenerate the packaged model after changing semantic catalogs."
            )

        if self._expected_concept_ids is None:
            return

        expected = {concept_id.value for concept_id in self._expected_concept_ids}
        actual = set(model.classifiers)
        missing = sorted(expected - actual)
        unexpected = sorted(actual - expected)

        if missing or unexpected:
            differences: list[str] = []

            if missing:
                differences.append(f"missing: {', '.join(missing)}")

            if unexpected:
                differences.append(f"unexpected: {', '.join(unexpected)}")

            raise ValueError(
                "Semantic concept model concepts do not match the runtime catalog "
                f"({'; '.join(differences)}). "
                "Regenerate the packaged model for this package build."
            )

    def score_probabilities(
        self,
        feature_names: tuple[str, ...],
    ) -> dict[ConceptId, float]:
        if self.model is None:
            raise RuntimeError("Semantic concept scorer has no model")

        return {
            ConceptId(concept_id): probability
            for concept_id, probability in self.model.score_probabilities(
                feature_names
            ).items()
        }


def train_concept_model(
    feature_rows: list[tuple[str, ...]],
    label_rows: list[tuple[ConceptId, ...]],
    concept_ids: tuple[ConceptId, ...],
    *,
    smoothing: float = DEFAULT_CONCEPT_SMOOTHING,
    metadata: Mapping[str, object] | None = None
) -> SemanticConceptLogOddsModel:
    classifiers: dict[str, ConceptLogOddsClassifier] = {}
    feature_support: Counter[str] = Counter()

    for features in feature_rows:
        feature_support.update(set(features))

    for concept_id in concept_ids:
        positive_indices = [index for index, labels in enumerate(label_rows) if concept_id in labels]
        negative_indices = [index for index, labels in enumerate(label_rows) if concept_id not in labels]
        positive_count = len(positive_indices)
        negative_count = len(negative_indices)
        prior_weight = math.log((positive_count + smoothing) / (negative_count + smoothing))
        feature_weights: dict[str, float] = {}

        if positive_count > 0 and negative_count > 0:
            positive_feature_counts: Counter[str] = Counter()
            negative_feature_counts: Counter[str] = Counter()
            all_features: set[str] = set()

            for index, features in enumerate(feature_rows):
                feature_set = _features_for_concept(concept_id, features)
                all_features.update(feature_set)

                if index in positive_indices:
                    positive_feature_counts.update(feature_set)
                else:
                    negative_feature_counts.update(feature_set)

            positive_denominator = positive_count + (2 * smoothing)
            negative_denominator = negative_count + (2 * smoothing)

            for feature in sorted(all_features):
                positive_probability = (
                    positive_feature_counts.get(feature, 0) + smoothing
                ) / positive_denominator
                negative_probability = (
                    negative_feature_counts.get(feature, 0) + smoothing
                ) / negative_denominator
                raw_feature_weight = math.log(
                    positive_probability / negative_probability
                )
                support = feature_support[feature]
                support_factor = support / (
                    support + CONCEPT_FEATURE_SUPPORT_SHRINKAGE
                )
                feature_weight = raw_feature_weight * support_factor
                feature_weights[feature] = max(
                    -MAX_CONCEPT_FEATURE_WEIGHT,
                    min(MAX_CONCEPT_FEATURE_WEIGHT, feature_weight)
                )

        classifiers[concept_id.value] = ConceptLogOddsClassifier(
            prior_weight=prior_weight,
            feature_weights=feature_weights,
            positive_examples=positive_count,
            negative_examples=negative_count
        )

    model_metadata: dict[str, object] = dict(metadata or {})
    model_metadata["feature_schema_version"] = SEMANTIC_FEATURE_SCHEMA_VERSION

    return SemanticConceptLogOddsModel(
        classifiers=classifiers,
        smoothing=smoothing,
        metadata=freeze_json_object(model_metadata, "training metadata")
    )
