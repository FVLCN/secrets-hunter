from secrets_hunter.detection.semantics.observation import FactId
from secrets_hunter.models import Disposition, RejectionKind, ValueKind

from .context import DecisionContext
from .models import DecisionPhase
from .rule_set import RuleSet
from ..signals import (
    has_direct_fixture_evidence,
    has_direct_hash_artifact_evidence,
    has_direct_identifier_evidence
)

rules = RuleSet(DecisionPhase.SEMANTIC)


@rules.when(
    priority=2400,
    disposition=Disposition.REPORT,
    confidence=lambda values: values.credential_with_hash_shaped_value,
    reasoning="credential classification with hash-shaped value",
)
def credential_with_hash_shape(context: DecisionContext) -> bool:
    rejection = context.observation.value_rejection
    has_hash_shape = (
        rejection is not None
        and rejection.kind is RejectionKind.HASH
    ) or (
        context.observation.value_kind is ValueKind.HEX
        and context.has_fact(FactId.HIGH_ENTROPY)
    )

    return (
        has_hash_shape
        and context.has_strong_direct_credential_evidence
        and not has_direct_fixture_evidence(context.evidence_by_concept)
    )


@rules.when(
    priority=2300,
    disposition=Disposition.REJECT,
    confidence=lambda values: values.artifact_reject,
    reasoning="non-secret artifact classification",
)
def artifact_classification(context: DecisionContext) -> bool:
    return (
        (
            bool(context.reject_evidence)
            or has_direct_hash_artifact_evidence(
                context.evidence_by_concept
            )
        )
        and not context.strong_secret_context
        and not context.has_strong_direct_credential_evidence
    )


@rules.when(
    priority=2200,
    disposition=Disposition.REJECT,
    confidence=lambda values: values.value_rejected,
    reasoning="value matched a rejection pattern",
)
def value_rejection(context: DecisionContext) -> bool:
    rejection = context.observation.value_rejection
    return (
        rejection is not None
        and rejection.kind not in {
            RejectionKind.PLACEHOLDER,
            RejectionKind.STRUCTURAL_PEM,
        }
        and not context.strong_secret_context
    )


@rules.when(
    priority=2100,
    disposition=Disposition.REJECT,
    confidence=lambda values: values.artifact_reject,
    reasoning="matched value is ordinary text",
)
def english_text_value(context: DecisionContext) -> bool:
    return (
        context.has_fact(FactId.ENGLISH_WORDS_IN_VALUE)
        and not context.strong_secret_context
    )


@rules.when(
    priority=1800,
    disposition=Disposition.REVIEW,
    reasoning="artifact context with credential classification",
)
def context_reject_with_credential(context: DecisionContext) -> bool:
    thresholds = context.policy.decision_thresholds
    has_identifier_context = (
        context.context_reject_probability >= thresholds.context_reject
        or has_direct_identifier_evidence(context.evidence_by_concept)
    )
    has_credential_context = (
        context.credential_probability >= thresholds.credential
        or context.has_strong_direct_credential_evidence
    )

    return (
        has_identifier_context
        and has_credential_context
    )


@rules.when(
    priority=1790,
    disposition=Disposition.REVIEW,
    reasoning="artifact context with secret-target classification",
)
def context_reject_with_target(context: DecisionContext) -> bool:
    thresholds = context.policy.decision_thresholds
    has_identifier_context = (
        context.context_reject_probability >= thresholds.context_reject
        or has_direct_identifier_evidence(context.evidence_by_concept)
    )
    has_credential_context = (
        context.credential_probability >= thresholds.credential
        or context.has_strong_direct_credential_evidence
    )

    return (
        has_identifier_context
        and not has_credential_context
        and context.target_probability >= thresholds.target
    )


@rules.when(
    priority=1780,
    disposition=Disposition.REJECT,
    reasoning="non-secret identifier context",
)
def context_reject(context: DecisionContext) -> bool:
    thresholds = context.policy.decision_thresholds
    has_identifier_context = (
        context.context_reject_probability >= thresholds.context_reject
        or has_direct_identifier_evidence(context.evidence_by_concept)
    )
    has_credential_context = (
        context.credential_probability >= thresholds.credential
        or context.has_strong_direct_credential_evidence
    )

    return (
        has_identifier_context
        and not has_credential_context
        and context.target_probability < thresholds.target
    )


RULES = rules.freeze()
