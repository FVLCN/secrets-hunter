from dataclasses import dataclass

from secrets_hunter.resources import (
    FrozenJsonObject,
    JsonObject,
    JsonValue,
    freeze_json_object
)


@dataclass(frozen=True)
class ConceptClassifierSpec:
    prior_weight: float
    feature_weights: tuple[tuple[str, float], ...]
    positive_examples: int
    negative_examples: int


@dataclass(frozen=True)
class ConceptModelSpec:
    model_type: str
    smoothing: float
    metadata: FrozenJsonObject
    classifiers: tuple[tuple[str, ConceptClassifierSpec], ...]


class ConceptModelDataValidator:
    @classmethod
    def parse(
        cls,
        data: JsonObject,
        expected_model_type: str,
        default_smoothing: float
    ) -> ConceptModelSpec:
        model_type = data.get("model_type")
        if model_type != expected_model_type:
            raise ValueError(
                f"Unsupported semantic concept model type: {model_type}"
            )

        smoothing = cls._require_number(
            data.get("smoothing", default_smoothing),
            "smoothing"
        )
        if smoothing <= 0:
            raise ValueError("Semantic concept model smoothing must be positive")

        metadata = cls._require_object(data.get("metadata", {}), "metadata")
        concepts = cls._require_object(data.get("concepts", {}), "concepts")
        classifiers = tuple(
            (
                concept_id,
                cls._classifier_spec(concept_id, concept_data)
            )
            for concept_id, concept_data in sorted(concepts.items())
        )

        return ConceptModelSpec(
            model_type=model_type,
            smoothing=smoothing,
            metadata=freeze_json_object(metadata, "model.metadata"),
            classifiers=classifiers
        )

    @classmethod
    def _classifier_spec(
        cls,
        concept_id: str,
        value: JsonValue
    ) -> ConceptClassifierSpec:
        path = f"concepts.{concept_id}"
        data = cls._require_object(value, path)
        feature_data = cls._require_object(
            data.get("feature_weights", {}),
            f"{path}.feature_weights"
        )
        feature_weights = tuple(
            (
                feature,
                cls._require_number(weight, f"{path}.feature_weights.{feature}")
            )
            for feature, weight in sorted(feature_data.items())
        )

        return ConceptClassifierSpec(
            prior_weight=cls._require_number(
                data.get("prior_weight"),
                f"{path}.prior_weight"
            ),
            feature_weights=feature_weights,
            positive_examples=cls._require_count(
                data.get("positive_examples", 0),
                f"{path}.positive_examples"
            ),
            negative_examples=cls._require_count(
                data.get("negative_examples", 0),
                f"{path}.negative_examples"
            )
        )

    @staticmethod
    def _require_object(value: JsonValue, path: str) -> JsonObject:
        if not isinstance(value, dict):
            raise ValueError(f"Semantic concept model {path} must be an object")
        return value

    @staticmethod
    def _require_number(value: JsonValue | None, path: str) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"Semantic concept model {path} must be a number")
        return float(value)

    @staticmethod
    def _require_count(value: JsonValue, path: str) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(
                f"Semantic concept model {path} must be a non-negative integer"
            )
        return value
