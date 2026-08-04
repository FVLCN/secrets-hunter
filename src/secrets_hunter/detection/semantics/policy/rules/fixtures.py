from secrets_hunter.models import Disposition

from .context import DecisionContext
from .models import DecisionPhase
from .rule_set import RuleSet

rules = RuleSet(DecisionPhase.SEMANTIC)


@rules.when(
    priority=2500,
    disposition=Disposition.REPORT,
    confidence=lambda values: values.strong_secret_context_with_fixture,
    reasoning="strong secret context despite fixture-like naming",
)
def fixture_with_strong_secret_context(context: DecisionContext) -> bool:
    return bool(context.hard_rejects) and context.strong_secret_context


@rules.when(
    priority=2490,
    disposition=Disposition.REVIEW,
    confidence=lambda values: values.context_reject_with_credential,
    reasoning="fixture-like context with credential classification",
)
def fixture_with_credential(context: DecisionContext) -> bool:
    thresholds = context.policy.decision_thresholds
    return (
        bool(context.hard_rejects)
        and not context.strong_secret_context
        and context.credential_probability >= thresholds.credential
    )


@rules.when(
    priority=2480,
    disposition=Disposition.REVIEW,
    confidence=lambda values: values.context_reject_with_target,
    reasoning="fixture-like context with secret-target classification",
)
def fixture_with_target(context: DecisionContext) -> bool:
    thresholds = context.policy.decision_thresholds
    return (
        bool(context.hard_rejects)
        and context.credential_probability < thresholds.credential
        and context.target_probability >= thresholds.target
    )


@rules.when(
    priority=2470,
    disposition=Disposition.REJECT,
    confidence=lambda values: values.context_reject,
    reasoning="fixture-like context without supporting secret classification",
)
def fixture_context(context: DecisionContext) -> bool:
    thresholds = context.policy.decision_thresholds
    return (
        bool(context.hard_rejects)
        and context.credential_probability < thresholds.credential
        and context.target_probability < thresholds.target
    )


RULES = rules.freeze()
