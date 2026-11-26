from secrets_hunter.models import Disposition

from .context import DecisionContext
from .models import DecisionPhase
from .rule_set import RuleSet

rules = RuleSet(DecisionPhase.SEMANTIC)


def _has_direct_secret_context(context: DecisionContext) -> bool:
    return (
        context.strong_secret_context
        and context.groups.matched(context.groups.targets)
    )


@rules.when(
    priority=2500,
    disposition=Disposition.REPORT,
    confidence=lambda values: values.strong_secret_context_with_fixture,
    reasoning="strong secret context despite fixture-like naming",
)
def fixture_with_strong_secret_context(context: DecisionContext) -> bool:
    return context.has_fixture_context and _has_direct_secret_context(context)


@rules.when(
    priority=2490,
    disposition=Disposition.REVIEW,
    confidence=lambda values: values.context_reject_with_credential,
    reasoning="fixture-like context with credential evidence",
)
def fixture_with_credential(context: DecisionContext) -> bool:
    return (
        context.has_fixture_context
        and not _has_direct_secret_context(context)
        and context.has_credential_context
    )


@rules.when(
    priority=2480,
    disposition=Disposition.REVIEW,
    confidence=lambda values: values.context_reject_with_credential,
    reasoning="credential evidence in reference documentation",
)
def reference_document_credential(context: DecisionContext) -> bool:
    return (
        context.observation.file_extension == ".md"
        and "references" in context.observation.path_tokens
        and context.has_strong_direct_credential_evidence
        and not context.groups.matched(context.groups.targets)
    )


@rules.when(
    priority=1750,
    disposition=Disposition.REVIEW,
    confidence=lambda values: values.context_reject_with_target,
    reasoning="fixture-like context with secret-target evidence",
)
def fixture_with_target(context: DecisionContext) -> bool:
    return (
        context.has_fixture_context
        and not context.has_credential_context
        and context.has_target_context
    )


@rules.when(
    priority=2470,
    disposition=Disposition.REJECT,
    confidence=lambda values: values.context_reject,
    reasoning="fixture-like context without supporting secret evidence",
)
def fixture_context(context: DecisionContext) -> bool:
    return (
        context.has_fixture_context
        and context.observation.value_rejection is None
        and not context.has_credential_context
        and not context.has_target_context
    )


RULES = rules.freeze()
