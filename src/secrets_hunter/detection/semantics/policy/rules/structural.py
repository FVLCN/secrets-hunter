from secrets_hunter.detection.semantics.observation import FactId
from secrets_hunter.detection.rejection_catalog import rejection_label
from secrets_hunter.models import Disposition, RejectionKind

from .context import DecisionContext
from .models import DecisionPhase
from .rule_set import RuleSet

rules = RuleSet(DecisionPhase.STRUCTURAL)


@rules.when(
    priority=300,
    disposition=Disposition.REJECT,
    confidence=lambda values: values.value_rejected_blocking,
    reasoning="assigned variable name is shorter than 3 characters",
)
def short_assignment_name(context: DecisionContext) -> bool:
    return (
        context.has_fact(FactId.SHORT_ASSIGNMENT_NAME)
        and context.has_fact(FactId.HIGH_ENTROPY)
    )


def _rejection_reasoning(context: DecisionContext) -> str:
    rejection = context.observation.value_rejection

    if (
        rejection is not None
        and rejection.kind is RejectionKind.PROVIDER_IDENTIFIER
    ):
        detail = rejection.detail or rejection.name
        return f"known non-secret provider identifier ({detail})"

    if rejection is not None and rejection.kind is RejectionKind.KNOWN_PUBLIC_SECRET:
        reasoning = "known public value"
        return f"{reasoning} ({rejection.detail})" if rejection.detail else reasoning

    if (
        context.groups.matched(context.groups.value_rejections)
        and (rejection is None or rejection.kind is not RejectionKind.PLACEHOLDER)
    ):
        return "explicit placeholder evidence"

    if rejection is None:
        return "rejected structured value"

    label = rejection_label(rejection)
    if label is not None:
        return label

    reasoning = " ".join(
        part.strip().lower()
        for part in (rejection.name, rejection.category)
        if part and part.strip()
    ) or "rejected structured value"

    return f"{reasoning} ({rejection.detail})" if rejection.detail else reasoning


@rules.when(
    priority=200,
    disposition=Disposition.REJECT,
    confidence=lambda values: values.value_rejected_blocking,
    reasoning=_rejection_reasoning,
)
def exact_value_rejection(context: DecisionContext) -> bool:
    rejection = context.observation.value_rejection
    return context.groups.matched(context.groups.value_rejections) or (
        rejection is not None and rejection.kind in {
            RejectionKind.PLACEHOLDER,
            RejectionKind.STRUCTURAL_PEM,
            RejectionKind.STRUCTURAL_VALUE,
            RejectionKind.PUBLIC_CRYPTO,
        }
    )


@rules.when(
    priority=150,
    disposition=Disposition.REJECT,
    reasoning=_rejection_reasoning,
)
def known_public_secret(context: DecisionContext) -> bool:
    rejection = context.observation.value_rejection
    return rejection is not None and rejection.kind is RejectionKind.KNOWN_PUBLIC_SECRET


@rules.when(
    priority=175,
    disposition=Disposition.REJECT,
    confidence=lambda values: values.value_rejected_blocking,
    reasoning=_rejection_reasoning,
)
def known_provider_identifier(context: DecisionContext) -> bool:
    rejection = context.observation.value_rejection
    return (
        rejection is not None
        and rejection.kind is RejectionKind.PROVIDER_IDENTIFIER
    )


@rules.when(
    priority=100,
    disposition=Disposition.REJECT,
    confidence=lambda values: values.artifact_reject,
    reasoning="public cryptographic artifact",
)
def public_crypto_artifact(context: DecisionContext) -> bool:
    return context.has_fact(FactId.PUBLIC_CRYPTO_ARTIFACT)


RULES = rules.freeze()
