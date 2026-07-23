from secrets_hunter.detection.semantics.catalog import ConceptId
from secrets_hunter.detection.semantics.observation import FactId
from secrets_hunter.models import Disposition, RejectionKind

from .context import DecisionContext
from .models import DecisionPhase
from .rule_set import RuleSet

rules = RuleSet(DecisionPhase.SEMANTIC)


@rules.when(
    priority=2400,
    disposition=Disposition.REPORT,
    confidence=lambda values: values.credential_with_hash_shaped_value,
    reasoning="credential classification with hash-shaped value",
)
def credential_with_hash_shape(context: DecisionContext) -> bool:
    thresholds = context.policy.decision_thresholds
    return (
        ConceptId.HASH_ARTIFACT in context.reject_evidence
        and context.credential_probability >= thresholds.credential
    )


@rules.when(
    priority=2300,
    disposition=Disposition.SUPPRESS,
    confidence=lambda values: values.artifact_reject,
    reasoning="non-secret artifact classification",
)
def artifact_classification(context: DecisionContext) -> bool:
    return bool(context.reject_evidence) and not context.strong_secret_context


@rules.when(
    priority=2200,
    disposition=Disposition.SUPPRESS,
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
    disposition=Disposition.SUPPRESS,
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
    return (
        context.context_reject_probability >= thresholds.context_reject
        and context.credential_probability >= thresholds.credential
    )


@rules.when(
    priority=1790,
    disposition=Disposition.REVIEW,
    reasoning="artifact context with secret-target classification",
)
def context_reject_with_target(context: DecisionContext) -> bool:
    thresholds = context.policy.decision_thresholds
    return (
        context.context_reject_probability >= thresholds.context_reject
        and context.credential_probability < thresholds.credential
        and context.target_probability >= thresholds.target
    )


@rules.when(
    priority=1780,
    disposition=Disposition.SUPPRESS,
    reasoning="non-secret identifier context",
)
def context_reject(context: DecisionContext) -> bool:
    thresholds = context.policy.decision_thresholds
    return (
        context.context_reject_probability >= thresholds.context_reject
        and context.credential_probability < thresholds.credential
        and context.target_probability < thresholds.target
    )


RULES = rules.freeze()
