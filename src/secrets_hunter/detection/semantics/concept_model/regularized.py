import math

from secrets_hunter.detection.semantics.catalog import ConceptId
from secrets_hunter.resources import JsonObject

from .features import name_overlap_scales
from .log_odds import (
    MIN_TARGET_PATH_SUPPORT_GROUPS,
    ConceptLogOddsClassifier,
    _NAME_FEATURE_PREFIXES,
    _SOURCE_SUPPORTED_TARGET_CONCEPTS,
    _features_for_concept,
)


_REGULARIZATION = 0.25
_MAX_SWEEPS = 1800
_GRADIENT_TOLERANCE = 1e-5


def _softplus(value: float) -> float:
    return max(value, 0.0) + math.log1p(math.exp(-abs(value)))


def _fit_classifier(
    rows: list[list[tuple[int, float]]],
    labels: list[int],
    sample_weights: list[float],
    constrained: list[bool],
) -> tuple[float, list[float], JsonObject]:
    columns: list[list[tuple[int, float]]] = [[] for _ in constrained]
    for index, row in enumerate(rows):
        for feature, value in row:
            columns[feature].append((index, value))

    total = sum(sample_weights)
    positive = sum(weight * label for weight, label in zip(sample_weights, labels))
    if not math.isfinite(total) or not 0 < positive < total:
        raise ValueError("Regularized targets require positive and negative labeled weight")

    probability = ConceptLogOddsClassifier._probability
    bias = math.log((positive + 0.1) / (total - positive + 0.1))
    coefficients = [0.0] * len(constrained)
    logits = [bias] * len(rows)
    probabilities = [probability(bias)] * len(rows)

    for sweep in range(_MAX_SWEEPS):
        gradient = sum(
            weight * (predicted - label)
            for weight, predicted, label in zip(sample_weights, probabilities, labels)
        )
        curvature = sum(
            weight * predicted * (1 - predicted)
            for weight, predicted in zip(sample_weights, probabilities)
        )
        delta = max(-4.0, min(4.0, -gradient / max(curvature, 1e-12)))
        for _ in range(28):
            change = sum(
                weight * (_softplus(value + delta) - _softplus(value) - label * delta)
                for weight, value, label in zip(sample_weights, logits, labels)
            )
            if change <= 1e-12:
                break
            delta *= 0.5
        else:
            raise ValueError("Regularized target intercept line search did not converge")
        bias += delta
        for index in range(len(rows)):
            logits[index] += delta
            probabilities[index] = probability(logits[index])

        for feature, column in enumerate(columns):
            old = coefficients[feature]
            gradient = _REGULARIZATION * old + sum(
                sample_weights[index] * value * (probabilities[index] - labels[index])
                for index, value in column
            )
            curvature = _REGULARIZATION + sum(
                sample_weights[index] * value * value
                * probabilities[index] * (1 - probabilities[index])
                for index, value in column
            )
            delta = max(-4.0, min(4.0, -gradient / curvature))
            if constrained[feature]:
                delta = min(delta, -old)
            for _ in range(28):
                change = sum(
                    sample_weights[index] * (
                        _softplus(logits[index] + delta * value)
                        - _softplus(logits[index]) - labels[index] * delta * value
                    )
                    for index, value in column
                ) + _REGULARIZATION * (old * delta + 0.5 * delta * delta)
                if change <= 1e-12:
                    break
                delta *= 0.5
            else:
                raise ValueError("Regularized target feature line search did not converge")
            coefficients[feature] += delta
            for index, value in column:
                logits[index] += delta * value
                probabilities[index] = probability(logits[index])

        maximum_gradient = abs(sum(
            weight * (predicted - label)
            for weight, predicted, label in zip(sample_weights, probabilities, labels)
        ))
        for feature, column in enumerate(columns):
            gradient = _REGULARIZATION * coefficients[feature] + sum(
                sample_weights[index] * value * (probabilities[index] - labels[index])
                for index, value in column
            )
            if constrained[feature] and coefficients[feature] == 0 and gradient <= 0:
                gradient = 0.0
            maximum_gradient = max(maximum_gradient, abs(gradient))
        if maximum_gradient < _GRADIENT_TOLERANCE:
            break
    else:
        raise ValueError("Regularized target fitting did not converge")

    return bias, coefficients, {
        "regularization": _REGULARIZATION,
        "sweeps": sweep + 1,
        "max_projected_gradient": maximum_gradient,
        "weighted_positive_mass": positive,
        "weighted_negative_mass": total - positive,
    }


def fit_target_classifiers(
    feature_rows: list[tuple[str, ...]],
    label_rows: list[tuple[ConceptId, ...]],
    *,
    support_groups: list[str],
    labeled_concepts: list[tuple[ConceptId, ...] | None],
    sample_weights: list[float],
) -> tuple[dict[str, ConceptLogOddsClassifier], dict[str, JsonObject]]:
    if not (
        len(feature_rows) == len(label_rows) == len(support_groups)
        == len(labeled_concepts) == len(sample_weights)
    ):
        raise ValueError("Regularized target inputs must align with training rows")
    if any(not math.isfinite(weight) or weight <= 0 for weight in sample_weights):
        raise ValueError("Regularized target weights must be positive and finite")

    classifiers: dict[str, ConceptLogOddsClassifier] = {}
    statistics: dict[str, JsonObject] = {}
    for concept_id in sorted(_SOURCE_SUPPORTED_TARGET_CONCEPTS):
        selected = [
            index for index, scope in enumerate(labeled_concepts)
            if scope is None or concept_id in scope
        ]
        feature_sets = [
            _features_for_concept(concept_id, feature_rows[index])
            for index in selected
        ]
        vocabulary = sorted(set().union(*feature_sets))
        feature_indices = {feature: index for index, feature in enumerate(vocabulary)}
        rows: list[list[tuple[int, float]]] = []
        positive_groups: dict[str, set[str]] = {}
        for index, features in zip(selected, feature_sets):
            name_features = [
                feature for feature in features if feature.startswith(_NAME_FEATURE_PREFIXES)
            ]
            name_scales = dict(zip(
                name_features,
                name_overlap_scales(
                    set(feature.partition("=")[2].split("_"))
                    for feature in name_features
                ),
            ))
            row: list[tuple[int, float]] = []
            for feature in sorted(features):
                value = name_scales.get(feature, 1.0)
                row.append((feature_indices[feature], value))
                if concept_id in label_rows[index]:
                    positive_groups.setdefault(feature, set()).add(support_groups[index])
            rows.append(row)

        constrained = [
            not positive_groups.get(feature)
            or (
                feature.startswith("path_token=")
                and len(positive_groups[feature]) < MIN_TARGET_PATH_SUPPORT_GROUPS
            )
            for feature in vocabulary
        ]
        labels = [int(concept_id in label_rows[index]) for index in selected]
        weights = [sample_weights[index] for index in selected]
        bias, coefficients, stats = _fit_classifier(rows, labels, weights, constrained)
        classifier = ConceptLogOddsClassifier(
            prior_weight=bias,
            feature_weights=dict(zip(vocabulary, coefficients)),
            positive_examples=sum(labels),
            negative_examples=len(labels) - sum(labels),
        )
        normalization_error = max((
            abs(
                classifier.score_probability(feature_rows[index])
                - classifier._probability(
                    bias + sum(coefficients[feature] * value for feature, value in row)
                )
            )
            for index, row in zip(selected, rows)
        ), default=0.0)
        if normalization_error > 1e-9:
            raise ValueError(f"Training and runtime normalization differ for {concept_id}")
        stats.update(
            training_rows=len(selected),
            runtime_normalization_error=normalization_error,
        )
        classifiers[concept_id.value] = classifier
        statistics[concept_id.value] = stats

    return classifiers, statistics
