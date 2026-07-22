from secrets_hunter.detection.semantics.observation import FactId
from secrets_hunter.models import Disposition

from .context import DecisionContext
from .models import DecisionPhase
from .rule_set import RuleSet

rules = RuleSet(DecisionPhase.SEMANTIC)


@rules.when(
    priority=2000,
    disposition=Disposition.REVIEW,
    confidence=lambda values: values.no_assignment_entropy_with_secret_evidence,
    reasoning="unassigned high-entropy value with secret classification",
)
def unassigned_high_entropy_with_secret_classification(
    context: DecisionContext,
) -> bool:
    return (
        context.has_fact(FactId.HIGH_ENTROPY)
        and context.has_fact(FactId.NO_ASSIGNMENT_CONTEXT)
        and context.has_secret_classification
    )


@rules.when(
    priority=1990,
    disposition=Disposition.SUPPRESS,
    confidence=lambda values: values.no_assignment_entropy,
    reasoning="unassigned high-entropy value",
)
def unassigned_high_entropy(context: DecisionContext) -> bool:
    return (
        context.has_fact(FactId.HIGH_ENTROPY)
        and context.has_fact(FactId.NO_ASSIGNMENT_CONTEXT)
        and not context.has_secret_classification
    )


@rules.when(
    priority=1600,
    disposition=Disposition.REVIEW,
    reasoning="high-entropy value in ordinary identifier context",
)
def neutral_high_entropy_identifier(context: DecisionContext) -> bool:
    thresholds = context.policy.decision_thresholds
    return (
        context.has_fact(FactId.HIGH_ENTROPY)
        and context.neutral_reject_probability >= thresholds.neutral_reject
    )


@rules.when(
    priority=1500,
    disposition=Disposition.REVIEW,
    reasoning="high-entropy value in unknown identifier context",
)
def unknown_high_entropy_identifier(context: DecisionContext) -> bool:
    thresholds = context.policy.decision_thresholds
    return (
        context.has_fact(FactId.HIGH_ENTROPY)
        and context.has_fact(FactId.UNKNOWN_IDENTIFIER_CONTEXT)
        and context.credential_probability < thresholds.credential
        and context.target_probability < thresholds.target
    )


@rules.when(
    priority=1400,
    disposition=Disposition.REVIEW,
    reasoning="assigned high-entropy value",
)
def high_entropy_assigned(context: DecisionContext) -> bool:
    thresholds = context.policy.decision_thresholds
    return (
        context.has_fact(FactId.HIGH_ENTROPY)
        and not context.has_fact(FactId.NO_ASSIGNMENT_CONTEXT)
        and context.credential_probability < thresholds.credential
        and context.target_probability < thresholds.target
    )


RULES = rules.freeze()
