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
    reasoning="unassigned high-entropy value with secret evidence",
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
    disposition=Disposition.REJECT,
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
    return (
        context.has_fact(FactId.HIGH_ENTROPY)
        and not context.has_strong_direct_credential_evidence
        and context.has_ordinary_context
    )


@rules.when(
    priority=1550,
    disposition=Disposition.REVIEW,
    confidence=lambda values: values.contextual_high_entropy_identifier,
    reasoning="high-entropy value in contextual non-secret identifier",
)
def contextual_high_entropy_identifier(context: DecisionContext) -> bool:
    return (
        context.has_fact(FactId.HIGH_ENTROPY)
        and not context.has_strong_direct_credential_evidence
        and (context.has_ordinary_context or context.has_reference_context)
    )


@rules.when(
    priority=1500,
    disposition=Disposition.REVIEW,
    reasoning="high-entropy value in unknown identifier context",
)
def unknown_high_entropy_identifier(context: DecisionContext) -> bool:
    return (
        context.has_fact(FactId.HIGH_ENTROPY)
        and context.has_fact(FactId.UNKNOWN_IDENTIFIER_CONTEXT)
        and not context.has_credential_context
        and not context.has_target_context
    )


@rules.when(
    priority=1400,
    disposition=Disposition.REVIEW,
    reasoning="assigned high-entropy value",
)
def high_entropy_assigned(context: DecisionContext) -> bool:
    return (
        context.has_fact(FactId.HIGH_ENTROPY)
        and not context.has_fact(FactId.NO_ASSIGNMENT_CONTEXT)
        and not context.has_credential_context
        and not context.has_target_context
    )


RULES = rules.freeze()
