import hashlib
import json
import math
import warnings

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
from secrets_hunter.detection.semantics.concept_model.log_odds import (
    _SOURCE_SUPPORTED_TARGET_CONCEPTS,
    _USAGE_CONCEPTS,
)
from secrets_hunter.detection.value_context import MAX_CONTEXT_BYTES, MAX_CONTEXT_LINES
from secrets_hunter.models import (
    DetectionMethod,
    FindingKind,
    RejectionKind,
    RejectionReason
)
from secrets_hunter.resources import load_toml, read_resource_bytes


POSITIVE_TRAINING_EXAMPLE_RESOURCES = (
    "semantics/positive/synthetic.toml",
    "semantics/positive/source_derived.toml",
    "semantics/positive/synthetic_identifiers.toml",
)
NEGATIVE_TRAINING_EXAMPLE_RESOURCES = (
    "semantics/negative/synthetic.toml",
    "semantics/negative/source_derived.toml",
    "semantics/negative/synthetic_identifiers.toml",
)
TRAINING_EXAMPLE_RESOURCES = (
    *POSITIVE_TRAINING_EXAMPLE_RESOURCES,
    *NEGATIVE_TRAINING_EXAMPLE_RESOURCES,
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
    associated_name: str
    value: str
    lexical_subject: str | None
    detection_method: DetectionMethod
    finding_kind: FindingKind
    file_path: str
    value_rejection: RejectionReason | None
    concept_labels: tuple[ConceptId, ...]
    support_group: str | None = None
    labeled_concepts: tuple[ConceptId, ...] | None = None
    sample_weight: float = 1.0
    source_context: str | None = None
    source_line: int | None = None


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
    concept_labels = tuple(
        require_concept_id(label, "concept label", source)
        for label in require_string_list(example_data, "concept_labels", source)
    )
    labeled_concepts = None
    if "labeled_concepts" in example_data:
        labeled_concepts = tuple(
            require_concept_id(label, "labeled concept", source)
            for label in require_string_list(example_data, "labeled_concepts", source)
        )
        if not labeled_concepts or not set(labeled_concepts).issubset(
            _SOURCE_SUPPORTED_TARGET_CONCEPTS | _USAGE_CONCEPTS
            | {ConceptId.IDENTIFIER_CONTEXT}
        ):
            raise ValueError(
                f"'labeled_concepts' must name supported target, usage, or identifier concepts in {source}"
            )
        if not set(concept_labels).issubset(labeled_concepts):
            raise ValueError(f"Concept labels must be within 'labeled_concepts' in {source}")

    sample_weight = example_data.get("sample_weight", 1.0)
    if (
        isinstance(sample_weight, bool)
        or not isinstance(sample_weight, (int, float))
        or not math.isfinite(sample_weight)
        or sample_weight <= 0
    ):
        raise ValueError(f"'sample_weight' must be positive and finite in {source}")
    if labeled_concepts is None and sample_weight != 1.0:
        raise ValueError(f"'sample_weight' requires scoped target labels in {source}")
    if sample_weight != 1.0 and set(labeled_concepts or ()) & _USAGE_CONCEPTS:
        raise ValueError(f"Usage concept examples require sample_weight = 1 in {source}")
    if sample_weight != 1.0 and ConceptId.IDENTIFIER_CONTEXT in (labeled_concepts or ()):
        warnings.warn(
            f"sample_weight={sample_weight} for {var_name!r} in {source} "
            "has no effect on identifier_context; it applies only to regularized targets.",
            stacklevel=2,
        )

    source_context = None
    source_line = example_data.get("source_line")
    if "source_context" in example_data:
        source_context = require_string(example_data["source_context"], "source_context", source)
        context_lines = source_context.splitlines()
        if len(source_context.encode("utf-8")) > MAX_CONTEXT_BYTES or len(context_lines) > MAX_CONTEXT_LINES:
            raise ValueError(f"'source_context' exceeds the supported bounds in {source}")
        if isinstance(source_line, bool) or not isinstance(source_line, int) or not 1 <= source_line <= len(context_lines):
            raise ValueError(f"'source_line' must locate a line in 'source_context' in {source}")
        if not set(labeled_concepts or ()).issubset(_USAGE_CONCEPTS) or labeled_concepts is None:
            raise ValueError(f"'source_context' requires scoped usage concept labels in {source}")
        value = require_string(example_data.get("value"), "value", source)
        if context_lines[source_line - 1].count(value) != 1:
            raise ValueError(f"'source_line' must contain the candidate exactly once in {source}")
    elif source_line is not None:
        raise ValueError(f"'source_line' requires 'source_context' in {source}")

    return SemanticExample(
        associated_name=require_string_or_empty(var_name, "var_name", source),
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
        concept_labels=concept_labels,
        support_group=(
            require_string(example_data["support_group"], "support_group", source)
            if "support_group" in example_data
            else None
        ),
        labeled_concepts=labeled_concepts,
        sample_weight=float(sample_weight),
        source_context=source_context,
        source_line=source_line,
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

        if not labels and "labeled_concepts" not in example_data:
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
    documents = []
    for path, resources in (
        (secret_training_examples_path, POSITIVE_TRAINING_EXAMPLE_RESOURCES),
        (false_positive_training_examples_path, NEGATIVE_TRAINING_EXAMPLE_RESOURCES),
    ):
        if path is not None:
            documents.append(load_toml(path))
        else:
            documents.extend(
                load_toml(fallback_resource=resource)
                for resource in resources
            )

    return tuple(
        example
        for document in documents
        for example in _load_training_examples(
            document.data,
            document.source,
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
