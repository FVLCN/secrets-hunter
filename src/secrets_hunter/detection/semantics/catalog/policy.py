from collections.abc import Mapping
from dataclasses import dataclass, fields, is_dataclass

from .parsing import _load_number_config


@dataclass(frozen=True)
class ReportingPolicy:
    concept_probability_threshold: float
    concept_limit: int


@dataclass(frozen=True)
class DecisionThresholds:
    reject: float
    context_reject: float
    neutral_reject: float
    credential: float
    target: float
    neutral: float
    strong_credential: float


@dataclass(frozen=True)
class ConfidencePolicy:
    value_rejected_blocking: float
    artifact_reject: float
    value_rejected: float
    no_assignment_entropy_with_secret_evidence: float
    no_assignment_entropy: float
    strong_secret_pattern: float
    strong_secret_context: float
    strong_secret_context_with_fixture: float
    known_pattern: float
    context_reject_with_credential: float
    context_reject_with_target: float
    context_reject: float
    neutral_bare_credential: float
    neutral_high_entropy_identifier: float
    contextual_high_entropy_identifier: float
    unknown_high_entropy_identifier: float
    high_entropy_assigned: float
    strong_credential: float
    credential_with_neutral: float
    credential_with_value_signal: float
    credential_with_hash_shaped_value: float
    credential_only: float
    target_only: float
    default: float


@dataclass(frozen=True)
class SemanticPolicyConfig:
    reporting: ReportingPolicy
    decision_thresholds: DecisionThresholds
    confidence: ConfidencePolicy


def _validate_probability_values(value: object, path: str) -> None:
    if not is_dataclass(value):
        raise TypeError(f"Policy value {path} must be a dataclass instance")

    for field in fields(value):
        field_value = getattr(value, field.name)
        field_path = f"{path}.{field.name}"

        if is_dataclass(field_value):
            _validate_probability_values(field_value, field_path)
        elif isinstance(field_value, float) and not 0.0 <= field_value <= 1.0:
            raise ValueError(f"Policy probability {field_path} must be between 0 and 1")


def _load_policy_config(
    data: Mapping[str, object],
    source: str
) -> SemanticPolicyConfig:
    policy = _load_number_config(data, SemanticPolicyConfig, "policy", source)

    if policy.reporting.concept_limit <= 0:
        raise ValueError("Policy reporting.concept_limit must be greater than zero")

    _validate_probability_values(policy, "policy")
    return policy
