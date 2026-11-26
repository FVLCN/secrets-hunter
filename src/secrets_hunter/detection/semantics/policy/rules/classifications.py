from secrets_hunter.detection.semantics.observation import FactId
from secrets_hunter.models import Disposition

from .context import DecisionContext
from .models import DecisionPhase
from .rule_set import RuleSet

rules = RuleSet(DecisionPhase.SEMANTIC)


@rules.when(
    priority=1900,
    disposition=Disposition.REPORT,
    reasoning="credential and secret-target evidence",
)
def strong_secret_context(context: DecisionContext) -> bool:
    return context.strong_secret_context


@rules.when(
    priority=1700,
    disposition=Disposition.REVIEW,
    confidence=lambda values: values.neutral_bare_credential,
    reasoning="inferred credential in ordinary identifier context",
)
def neutral_credential_context(context: DecisionContext) -> bool:
    return (
        context.has_ordinary_context
        and context.has_credential_context
        and not context.has_strong_direct_credential_evidence
        and not context.has_target_context
        and not context.has_fact(FactId.HIGH_ENTROPY)
    )


@rules.when(
    priority=1300,
    disposition=Disposition.REVIEW,
    reasoning="inferred credential requires review",
)
def strong_credential(context: DecisionContext) -> bool:
    return (
        context.has_credential_context
        and not context.has_strong_direct_credential_evidence
    )


def _subordinate_credential_context(context: DecisionContext) -> bool:
    return (
        context.has_credential_context
        and not context.has_strong_inferred_credential
        and not context.has_target_context
    )


def _credential_entropy_condition(context: DecisionContext) -> bool:
    return (
        context.has_fact(FactId.HIGH_ENTROPY)
        and context.has_strong_direct_credential_evidence
    )


@rules.when(
    priority=1200,
    disposition=Disposition.REPORT,
    confidence=lambda values: values.credential_with_value_signal,
    reasoning="credential evidence with high entropy",
)
def credential_with_entropy(context: DecisionContext) -> bool:
    return _credential_entropy_condition(context)


@rules.when(
    priority=1180,
    disposition=Disposition.REVIEW,
    confidence=lambda values: values.credential_with_neutral,
    reasoning="credential evidence in neutral context",
)
def credential_with_neutral_context(context: DecisionContext) -> bool:
    return (
        _subordinate_credential_context(context)
        and not _credential_entropy_condition(context)
        and context.has_neutral_context
    )


@rules.when(
    priority=1170,
    disposition=Disposition.REVIEW,
    reasoning="credential evidence without corroborating target",
)
def credential_only(context: DecisionContext) -> bool:
    return (
        _subordinate_credential_context(context)
        and not _credential_entropy_condition(context)
        and not context.has_neutral_context
    )


@rules.when(
    priority=1100,
    disposition=Disposition.REVIEW,
    reasoning="secret-target evidence without credential evidence",
)
def target_only(context: DecisionContext) -> bool:
    return not context.has_credential_context and context.has_target_context


RULES = rules.freeze()
