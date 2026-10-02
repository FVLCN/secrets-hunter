from secrets_hunter.detection.semantics.observation import FactId
from secrets_hunter.models import Disposition

from .context import DecisionContext
from .models import DecisionPhase
from .rule_set import RuleSet

rules = RuleSet(DecisionPhase.SEMANTIC)


@rules.when(
    priority=1900,
    disposition=Disposition.REPORT,
    reasoning="credential and secret-target classifications",
)
def strong_secret_context(context: DecisionContext) -> bool:
    return context.strong_secret_context


@rules.when(
    priority=1700,
    disposition=Disposition.REVIEW,
    confidence=lambda values: values.neutral_bare_credential,
    reasoning="credential classification in ordinary identifier context",
)
def neutral_credential_context(context: DecisionContext) -> bool:
    thresholds = context.policy.decision_thresholds
    return (
        context.neutral_reject_probability >= thresholds.neutral_reject
        and context.credential_probability >= thresholds.credential
        and context.target_probability < thresholds.target
        and not context.has_fact(FactId.HIGH_ENTROPY)
    )


@rules.when(
    priority=1300,
    disposition=Disposition.REPORT,
    reasoning="strong credential classification",
)
def strong_credential(context: DecisionContext) -> bool:
    return (
        context.credential_probability
        >= context.policy.decision_thresholds.strong_credential
    )


def _subordinate_credential_context(context: DecisionContext) -> bool:
    thresholds = context.policy.decision_thresholds
    return (
        thresholds.credential
        <= context.credential_probability
        < thresholds.strong_credential
        and context.target_probability < thresholds.target
    )


def _credential_entropy_condition(context: DecisionContext) -> bool:
    return (
        context.has_fact(FactId.HIGH_ENTROPY)
        and (
            _subordinate_credential_context(context)
            or context.has_strong_direct_credential_evidence
        )
    )


@rules.when(
    priority=1200,
    disposition=Disposition.REPORT,
    confidence=lambda values: values.credential_with_value_signal,
    reasoning="credential classification with high entropy",
)
def credential_with_entropy(context: DecisionContext) -> bool:
    return _credential_entropy_condition(context)


@rules.when(
    priority=1180,
    disposition=Disposition.REVIEW,
    confidence=lambda values: values.credential_with_neutral,
    reasoning="credential classification in neutral context",
)
def credential_with_neutral_context(context: DecisionContext) -> bool:
    thresholds = context.policy.decision_thresholds
    return (
        _subordinate_credential_context(context)
        and not _credential_entropy_condition(context)
        and context.neutral_probability >= thresholds.neutral
    )


@rules.when(
    priority=1170,
    disposition=Disposition.REVIEW,
    reasoning="credential classification without corroborating target",
)
def credential_only(context: DecisionContext) -> bool:
    thresholds = context.policy.decision_thresholds
    return (
        _subordinate_credential_context(context)
        and not _credential_entropy_condition(context)
        and context.neutral_probability < thresholds.neutral
    )


@rules.when(
    priority=1100,
    disposition=Disposition.REVIEW,
    reasoning="secret-target classification without credential classification",
)
def target_only(context: DecisionContext) -> bool:
    thresholds = context.policy.decision_thresholds
    return (
        context.credential_probability < thresholds.credential
        and context.target_probability >= thresholds.target
    )


RULES = rules.freeze()
