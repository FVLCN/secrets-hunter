from secrets_hunter.detection.semantics.observation.models import SemanticObservation
from secrets_hunter.detection.semantics.observation.facts import FactId


SEMANTIC_FEATURE_SCHEMA_VERSION = 1


def concept_feature_names(
    observation: SemanticObservation
) -> tuple[str, ...]:
    features: list[str] = []

    for fact in sorted(observation.facts):
        features.append(f"fact={fact}")

    if not observation.has_fact(FactId.NO_ASSIGNMENT_CONTEXT):
        features.append("name_present")

    for token in observation.name_tokens:
        features.append(f"name_token={token}")

    for left, right in zip(observation.name_tokens, observation.name_tokens[1:]):
        features.append(f"name_bigram={left}_{right}")

    for left, middle, right in zip(
        observation.name_tokens,
        observation.name_tokens[1:],
        observation.name_tokens[2:]
    ):
        features.append(f"name_trigram={left}_{middle}_{right}")

    if observation.neutral_identifier_tokens:
        features.append("neutral_identifier_present")

        for token in observation.neutral_identifier_tokens:
            features.append(f"neutral_identifier_token={token}")

    if observation.file_extension:
        features.append(f"file_extension={observation.file_extension}")

    for token in observation.path_tokens:
        features.append(f"path_token={token}")

    features.append(f"value_kind={observation.value_kind.value}")
    features.append(f"value_length={observation.value_length_bucket}")
    features.append(f"value_entropy={observation.value_entropy_bucket}")

    features.append(
        f"finding_kind={observation.finding_kind.id}"
    )
    value_rejection = observation.value_rejection

    if value_rejection is not None:
        features.append("fact=value_rejected")
        features.append(f"value_rejection_name={value_rejection.name.lower()}")

        features.append(
            f"value_rejection_category={value_rejection.category.lower()}"
        )

    return tuple(dict.fromkeys(features))
