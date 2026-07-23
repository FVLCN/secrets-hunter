import hashlib
import json

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from secrets_hunter.detection.finding_kinds import FindingKindRegistry
from secrets_hunter.detection.semantics.parsing import (
    normalize_token,
    require_string,
    require_string_list,
    require_string_or_empty,
    require_table
)
from secrets_hunter.detection.semantics.catalog.sources import (
    NEGATIVE_CONCEPTS_RESOURCE,
    NEGATIVE_EVIDENCE_RESOURCE,
    POSITIVE_CONCEPTS_RESOURCE,
    POSITIVE_EVIDENCE_RESOURCE,
    PROVIDER_PATTERNS_RESOURCE,
    PROVIDERS_RESOURCE,
)
from secrets_hunter.detection.semantics.catalog.taxonomy import (
    ConceptId,
    require_concept_id,
)
from secrets_hunter.models import (
    DetectionMethod,
    FindingKind,
    RejectionKind,
    RejectionReason
)
from secrets_hunter.resources import load_toml, read_resource_bytes


POSITIVE_TRAINING_EXAMPLES_RESOURCE = "semantics/positive/training_examples.toml"
NEGATIVE_TRAINING_EXAMPLES_RESOURCE = "semantics/negative/training_examples.toml"
TRAINING_EXAMPLE_RESOURCES = (
    POSITIVE_TRAINING_EXAMPLES_RESOURCE,
    NEGATIVE_TRAINING_EXAMPLES_RESOURCE,
)
MODEL_TRAINING_RESOURCES = (
    POSITIVE_CONCEPTS_RESOURCE,
    NEGATIVE_CONCEPTS_RESOURCE,
    POSITIVE_EVIDENCE_RESOURCE,
    NEGATIVE_EVIDENCE_RESOURCE,
    PROVIDERS_RESOURCE,
    PROVIDER_PATTERNS_RESOURCE,
    *TRAINING_EXAMPLE_RESOURCES,
)


@dataclass(frozen=True)
class SemanticExample:
    name: str
    value: str
    lexical_subject: str | None
    detection_method: DetectionMethod
    finding_kind: FindingKind
    file_path: str
    value_rejection: RejectionReason | None
    concept_labels: tuple[ConceptId, ...]


def _load_detection_method(
    example_data: Mapping[str, object],
    source: str
) -> DetectionMethod:
    raw_detector = normalize_token(
        require_string(example_data.get("detector"), "detector", source)
    )

    try:
        return DetectionMethod(raw_detector)
    except ValueError as exc:
        expected = ", ".join(method.value for method in DetectionMethod)
        raise ValueError(
            f"Unknown detector {raw_detector!r} in {source}; expected one of: {expected}"
        ) from exc


def _load_value_rejection(
    example_data: Mapping[str, object],
    source: str
) -> RejectionReason | None:
    value_rejected = example_data.get("value_rejected", False)

    if not isinstance(value_rejected, bool):
        raise ValueError(f"'value_rejected' must be a boolean in {source}")

    if not value_rejected:
        rejection_fields = {
            "rejection_kind",
            "rejection_pattern",
            "rejection_category",
        }
        unexpected = sorted(rejection_fields & example_data.keys())

        if unexpected:
            raise ValueError(
                f"{', '.join(unexpected)} require value_rejected = true in {source}"
            )

        return None

    raw_kind = example_data.get("rejection_kind", RejectionKind.GENERIC.value)

    if raw_kind is None:
        raw_kind = RejectionKind.GENERIC.value

    if not isinstance(raw_kind, str):
        raise ValueError(f"'rejection_kind' must be a string in {source}")

    normalized = normalize_token(raw_kind)

    try:
        kind = RejectionKind(normalized)
    except ValueError as exc:
        expected = ", ".join(kind.value for kind in RejectionKind)
        raise ValueError(
            f"Unknown rejection kind {normalized!r} in {source}; expected one of: {expected}"
        ) from exc

    return RejectionReason(
        kind=kind,
        name=require_string(
            example_data.get("rejection_pattern"),
            "rejection_pattern",
            source
        ),
        category=require_string(
            example_data.get("rejection_category"),
            "rejection_category",
            source
        )
    )


def _load_example(
    example_data: Mapping[str, object],
    source: str,
    finding_kinds: FindingKindRegistry
) -> SemanticExample:
    var_name = example_data.get("var_name", "")
    raw_lexical_subject = example_data.get("lexical_subject")

    return SemanticExample(
        name=require_string_or_empty(var_name, "var_name", source),
        value=require_string(example_data.get("value"), "value", source),
        lexical_subject=(
            require_string_or_empty(
                raw_lexical_subject,
                "lexical_subject",
                source
            )
            if raw_lexical_subject is not None
            else None
        ),
        detection_method=_load_detection_method(example_data, source),
        finding_kind=finding_kinds.require(
            require_string(
                example_data.get("finding_kind_id"),
                "finding_kind_id",
                source
            ),
            source
        ),
        file_path=require_string(example_data.get("file_path"), "file_path", source),
        value_rejection=_load_value_rejection(example_data, source),
        concept_labels=tuple(
            require_concept_id(label, "concept label", source)
            for label in require_string_list(example_data, "concept_labels", source)
        )
    )


def _load_training_examples(
    data: Mapping[str, object],
    source: str,
    finding_kinds: FindingKindRegistry
) -> tuple[SemanticExample, ...]:
    raw_examples = data.get("training_examples") or []

    if not isinstance(raw_examples, list):
        raise ValueError(f"'training_examples' must be an array in {source}")

    examples: list[SemanticExample] = []

    for raw_example in raw_examples:
        example_data = require_table(
            raw_example,
            "training_examples entry",
            source
        )

        labels = require_string_list(example_data, "concept_labels", source)

        if not labels:
            var_name = example_data.get("var_name", "")
            raise ValueError(
                f"Example {var_name!r} in {source} must include at least one concept label"
            )

        examples.append(
            _load_example(example_data, source, finding_kinds)
        )

    return tuple(examples)


def load_semantic_training_examples(
    finding_kinds: FindingKindRegistry,
    *,
    secret_training_examples_path: str | Path | None = None,
    false_positive_training_examples_path: str | Path | None = None
) -> tuple[SemanticExample, ...]:
    secret_document = load_toml(
        secret_training_examples_path,
        fallback_resource=POSITIVE_TRAINING_EXAMPLES_RESOURCE
    )
    false_positive_document = load_toml(
        false_positive_training_examples_path,
        fallback_resource=NEGATIVE_TRAINING_EXAMPLES_RESOURCE
    )

    return (
        _load_training_examples(
            secret_document.data,
            secret_document.source,
            finding_kinds
        )
        + _load_training_examples(
            false_positive_document.data,
            false_positive_document.source,
            finding_kinds
        )
    )


def semantic_model_source_hashes() -> dict[str, str]:
    return {
        resource_name: hashlib.sha256(read_resource_bytes(resource_name)).hexdigest()
        for resource_name in MODEL_TRAINING_RESOURCES
    }


def semantic_training_dataset_hash() -> str:
    dataset_hashes = {
        resource_name: hashlib.sha256(read_resource_bytes(resource_name)).hexdigest()
        for resource_name in TRAINING_EXAMPLE_RESOURCES
    }
    canonical = json.dumps(
        dataset_hashes,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()
