from secrets_hunter.detection.semantics.observation import FactId
from secrets_hunter.models import Disposition, RejectionKind

from .context import DecisionContext
from .models import DecisionPhase
from .rule_set import RuleSet

rules = RuleSet(DecisionPhase.STRUCTURAL)


def _rejection_reasoning(context: DecisionContext) -> str:
    rejection = context.observation.value_rejection

    if rejection is None:
        return "rejected structured value"

    return " ".join(
        part.strip().lower()
        for part in (rejection.name, rejection.category)
        if part and part.strip()
    ) or "rejected structured value"


@rules.when(
    priority=200,
    disposition=Disposition.REJECT,
    confidence=lambda values: values.value_rejected_blocking,
    reasoning=_rejection_reasoning,
)
def exact_value_rejection(context: DecisionContext) -> bool:
    rejection = context.observation.value_rejection
    return rejection is not None and rejection.kind in {
        RejectionKind.PLACEHOLDER,
        RejectionKind.STRUCTURAL_PEM,
    }


@rules.when(
    priority=100,
    disposition=Disposition.REJECT,
    confidence=lambda values: values.artifact_reject,
    reasoning="public cryptographic artifact",
)
def public_crypto_artifact(context: DecisionContext) -> bool:
    return context.has_fact(FactId.PUBLIC_CRYPTO_ARTIFACT)


RULES = rules.freeze()
