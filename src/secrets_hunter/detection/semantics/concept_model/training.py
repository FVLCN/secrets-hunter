import hashlib
import json

from dataclasses import dataclass
from pathlib import Path

from secrets_hunter.detection.semantics.concept_model.features import concept_feature_names
from secrets_hunter.detection.semantics.concept_model.log_odds import (
    DEFAULT_CONCEPT_SMOOTHING,
    train_concept_model as fit_concept_model
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


@dataclass(frozen=True)
class ConceptModelTrainingResult:
    concept_count: int
    training_example_count: int
    label_assignment_count: int
    output_path: Path
    model_sha256: str


def _semantic_input_from_example(
    example: SemanticExample,
    value_analyzer: ValueAnalyzer
) -> SemanticInput:
    return SemanticInput(
        associated_name=example.associated_name,
        detection_method=example.detection_method,
        finding_kind=example.finding_kind,
        file_path=example.file_path,
        value_analysis=value_analyzer.analyze(example.value),
        lexical_subject=example.lexical_subject,
        value_rejection=example.value_rejection
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
) -> tuple[list[tuple[str, ...]], list[tuple[ConceptId, ...]], list[str]]:
    feature_rows: list[tuple[str, ...]] = []
    concept_label_rows: list[tuple[ConceptId, ...]] = []
    example_names: list[str] = []
    observation_builder = SemanticObservationBuilder(catalog)
    value_analyzer = ValueAnalyzer(
        build_default_value_classifier()
    )

    for example in training_examples:
        item = _semantic_input_from_example(example, value_analyzer)
        observation = observation_builder.build(item)
        feature_rows.append(concept_feature_names(observation))
        concept_label_rows.append(_validated_training_labels(catalog, example))
        example_names.append(example.associated_name)

    return feature_rows, concept_label_rows, example_names


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
    feature_rows, concept_label_rows, example_names = _training_rows_from_catalog(
        catalog,
        training_examples
    )

    if not feature_rows:
        raise ValueError("Semantic catalogs must include at least one training example.")

    model = fit_concept_model(
        feature_rows,
        concept_label_rows,
        catalog.concept_ids,
        smoothing=smoothing,
        metadata={
            "ontology_version": SEMANTIC_ONTOLOGY_VERSION,
            "dataset_hash": semantic_training_dataset_hash(),
            "source_hashes": semantic_model_source_hashes(),
        }
    )
    output_path = Path(output).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    model_bytes = (
        json.dumps(model.to_dict(), indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    output_path.write_bytes(model_bytes)

    return ConceptModelTrainingResult(
        concept_count=len(catalog.concepts),
        training_example_count=len(example_names),
        label_assignment_count=sum(len(labels) for labels in concept_label_rows),
        output_path=output_path,
        model_sha256=hashlib.sha256(model_bytes).hexdigest()
    )
