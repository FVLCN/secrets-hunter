import hashlib
import json

from dataclasses import dataclass, replace
from pathlib import Path

from secrets_hunter.detection.semantics.concept_model.features import concept_feature_names
from secrets_hunter.detection.semantics.concept_model.log_odds import (
    DEFAULT_CONCEPT_SMOOTHING,
    SemanticConceptLogOddsModel,
    _SOURCE_SUPPORTED_TARGET_CONCEPTS,
    _USAGE_CONCEPTS,
    _USAGE_FACT_FEATURES,
    train_concept_model as fit_concept_model
)
from secrets_hunter.detection.semantics.concept_model.regularized import (
    fit_target_classifiers,
)
from secrets_hunter.detection.semantics.catalog import (
    SEMANTIC_ONTOLOGY_VERSION,
    ConceptId,
    SemanticCatalog,
    load_semantic_catalog,
)
from secrets_hunter.detection.semantics.concept_model.training_data import (
    SemanticExample,
    load_semantic_training_examples,
    semantic_model_source_hashes,
    semantic_training_dataset_hash,
)
from secrets_hunter.detection.semantics.observation import (
    SemanticInput,
    SemanticObservationBuilder,
)
from secrets_hunter.detection.default_value_classification import (
    build_default_value_classifier
)
from secrets_hunter.detection.provider_registry import (
    finding_kind_registry_for_catalog
)
from secrets_hunter.detection.value_analysis import ValueAnalyzer
from secrets_hunter.detection.fragmenter.models import SourceContext
from secrets_hunter.detection.value_context import value_context_fact_records


@dataclass(frozen=True)
class ConceptModelTrainingResult:
    concept_count: int
    training_example_count: int
    label_assignment_count: int
    output_path: Path
    model_sha256: str


def _semantic_input_from_example(
    example: SemanticExample,
    value_analyzer: ValueAnalyzer,
    provider_pattern_ids: frozenset[str],
) -> SemanticInput:
    return SemanticInput(
        associated_name=example.associated_name,
        detection_method=example.detection_method,
        finding_kind=example.finding_kind,
        file_path=example.file_path,
        value_analysis=value_analyzer.analyze(example.value),
        lexical_subject=example.lexical_subject,
        value_rejection=example.value_rejection,
        provider_pattern_id=(
            example.finding_kind.id
            if example.finding_kind.id in provider_pattern_ids
            else None
        ),
        usage_facts=value_context_fact_records(
            SourceContext(example.source_context, 1) if example.source_context is not None else None,
            candidate_line=example.source_line or 1,
            candidate_value=example.value,
            file_path=example.file_path
        ),
    )


def _validated_training_labels(
    catalog: SemanticCatalog,
    example: SemanticExample
) -> tuple[ConceptId, ...]:
    labels = set(example.concept_labels)
    unknown = labels - set(catalog.concept_ids)

    if unknown:
        raise ValueError(
            f"Example {example.associated_name!r} references unknown concepts: "
            f"{', '.join(sorted(unknown))}"
        )

    return tuple(
        concept_id
        for concept_id in catalog.concept_ids
        if concept_id in labels
    )


def _training_rows_from_catalog(
    catalog: SemanticCatalog,
    training_examples: tuple[SemanticExample, ...]
) -> tuple[list[tuple[str, ...]], list[tuple[ConceptId, ...]]]:
    feature_rows: list[tuple[str, ...]] = []
    concept_label_rows: list[tuple[ConceptId, ...]] = []
    observation_builder = SemanticObservationBuilder(catalog)
    value_analyzer = ValueAnalyzer(
        build_default_value_classifier()
    )
    provider_pattern_ids = frozenset(pattern.id for pattern in catalog.provider_patterns)

    for example in training_examples:
        item = _semantic_input_from_example(
            example, value_analyzer, provider_pattern_ids
        )
        observation = observation_builder.build(item)
        feature_rows.append(concept_feature_names(observation))
        concept_label_rows.append(_validated_training_labels(catalog, example))

    return feature_rows, concept_label_rows


def train_model(
    *,
    output: str | Path,
    smoothing: float = DEFAULT_CONCEPT_SMOOTHING
) -> ConceptModelTrainingResult:
    if smoothing <= 0:
        raise ValueError("smoothing must be greater than zero")

    catalog = load_semantic_catalog()
    finding_kinds = finding_kind_registry_for_catalog(catalog)
    training_examples = load_semantic_training_examples(finding_kinds)
    feature_rows, concept_label_rows = _training_rows_from_catalog(
        catalog,
        training_examples
    )

    if not feature_rows:
        raise ValueError("Semantic catalogs must include at least one training example.")

    support_groups = [
        f"source:{example.support_group}"
        if example.support_group is not None
        else f"file:{example.file_path}"
        for example in training_examples
    ]
    legacy_indices = [
        index for index, example in enumerate(training_examples)
        if example.labeled_concepts is None
    ]
    if not legacy_indices:
        raise ValueError("Legacy concepts require complete-label training examples")

    legacy_model = fit_concept_model(
        [feature_rows[index] for index in legacy_indices],
        [concept_label_rows[index] for index in legacy_indices],
        tuple(
            concept_id
            for concept_id in catalog.concept_ids
            if concept_id not in _SOURCE_SUPPORTED_TARGET_CONCEPTS
            and concept_id is not ConceptId.IDENTIFIER_CONTEXT
        ),
        support_groups=[support_groups[index] for index in legacy_indices],
        smoothing=smoothing,
        metadata={
            "ontology_version": SEMANTIC_ONTOLOGY_VERSION,
            "dataset_hash": semantic_training_dataset_hash(),
            "source_hashes": semantic_model_source_hashes(),
        }
    )
    target_classifiers, target_statistics = fit_target_classifiers(
        feature_rows,
        concept_label_rows,
        support_groups=support_groups,
        labeled_concepts=[example.labeled_concepts for example in training_examples],
        sample_weights=[example.sample_weight for example in training_examples],
    )
    classifiers = {**legacy_model.classifiers, **target_classifiers}
    identifier_indices = [
        index for index, example in enumerate(training_examples)
        if example.labeled_concepts is None
        or ConceptId.IDENTIFIER_CONTEXT in example.labeled_concepts
    ]
    classifiers.update(fit_concept_model(
        [feature_rows[index] for index in identifier_indices],
        [concept_label_rows[index] for index in identifier_indices],
        (ConceptId.IDENTIFIER_CONTEXT,),
        smoothing=smoothing,
    ).classifiers)
    usage_statistics: dict[str, dict[str, int]] = {}
    for concept_id in sorted(_USAGE_CONCEPTS):
        usage_indices = [
            index for index, example in enumerate(training_examples)
            if example.labeled_concepts is not None and concept_id in example.labeled_concepts
        ]
        if not usage_indices:
            continue
        selected = legacy_indices + usage_indices
        usage_fit = fit_concept_model(
            [feature_rows[index] for index in selected],
            [concept_label_rows[index] for index in selected],
            (concept_id,),
            smoothing=smoothing
        ).classifiers[concept_id.value]
        extra_weights = {
            feature: weight
            for feature, weight in usage_fit.feature_weights.items()
            if feature in _USAGE_FACT_FEATURES
        }
        base = classifiers[concept_id.value]
        classifiers[concept_id.value] = replace(
            base,
            feature_weights={**base.feature_weights, **extra_weights}
        )
        usage_statistics[concept_id.value] = {
            "training_rows": len(selected),
            "positive_examples": usage_fit.positive_examples,
            "negative_examples": usage_fit.negative_examples,
            "added_features": len(extra_weights),
        }
    model = SemanticConceptLogOddsModel(
        classifiers=classifiers,
        smoothing=smoothing,
        metadata={
            **legacy_model.metadata,
            "training_algorithm_by_concept": {
                concept_id.value: (
                    "log_odds_plus_usage" if concept_id.value in usage_statistics
                    else "joint_logistic_l2" if concept_id in target_classifiers else "log_odds"
                )
                for concept_id in catalog.concept_ids
            },
            "training_example_count": len(training_examples),
            "legacy_training_example_count": len(legacy_indices),
            "scoped_training_example_count": len(training_examples) - len(legacy_indices),
            "target_solver": target_statistics,
            "usage_training": usage_statistics,
        },
    )
    output_path = Path(output).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    model_bytes = (
        json.dumps(model.to_dict(), indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    output_path.write_bytes(model_bytes)

    return ConceptModelTrainingResult(
        concept_count=len(catalog.concepts),
        training_example_count=len(training_examples),
        label_assignment_count=sum(len(labels) for labels in concept_label_rows),
        output_path=output_path,
        model_sha256=hashlib.sha256(model_bytes).hexdigest()
    )
