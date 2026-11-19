from secrets_hunter.detection.semantics.catalog import ConceptId
from secrets_hunter.detection.semantics.observation import FactId
from secrets_hunter.models import Disposition, RejectionKind, ValueKind

from .context import DecisionContext
from .models import DecisionPhase
from .rule_set import RuleSet

rules = RuleSet(DecisionPhase.SEMANTIC)


@rules.when(
    priority=2510,
    disposition=Disposition.REJECT,
    confidence=lambda values: values.artifact_reject,
    reasoning="value rejection classification without strong credential evidence",
)
def value_rejection_classification(context: DecisionContext) -> bool:
    return (
        context.has_value_rejection_context
        and not context.has_strong_direct_credential_evidence
    )


@rules.when(
    priority=2505,
    disposition=Disposition.REJECT,
    reasoning="explicit public credential name",
)
def public_credential_name(context: DecisionContext) -> bool:
    return (
        "public" in context.observation.name_tokens
        and context.has_strong_direct_credential_evidence
    )


@rules.when(
    priority=2450,
    disposition=Disposition.REVIEW,
    reasoning="conflicting credential and non-secret context evidence",
)
def context_reject_with_credential(context: DecisionContext) -> bool:
    return context.has_role_conflict


@rules.when(
    priority=2400,
    disposition=Disposition.REPORT,
    confidence=lambda values: values.credential_with_hash_shaped_value,
    reasoning="credential evidence with hash-shaped value",
)
def credential_with_hash_shape(context: DecisionContext) -> bool:
    rejection = context.observation.value_rejection
    has_hash_shape = (
        context.has_fact(FactId.HASH_SHAPED_VALUE)
        or (rejection is not None and rejection.kind is RejectionKind.HASH)
        or (
            context.observation.value_kind is ValueKind.HEX
            and context.has_fact(FactId.HIGH_ENTROPY)
        )
    )
    return (
        has_hash_shape
        and context.has_strong_direct_credential_evidence
        and not context.has_fixture_context
        and not context.has_role_conflict
    )


@rules.when(
    priority=2300,
    disposition=Disposition.REJECT,
    confidence=lambda values: values.artifact_reject,
    reasoning="non-secret artifact evidence",
)
def artifact_classification(context: DecisionContext) -> bool:
    return context.has_artifact_context and not context.has_credential_context


def _value_rejection_reasoning(context: DecisionContext) -> str:
    rejection = context.observation.value_rejection
    if rejection is None:
        return "value matched a rejection pattern"

    return (
        f"value matched a rejection pattern: {rejection.name} "
        f"({rejection.category})"
    )


@rules.when(
    priority=2200,
    disposition=Disposition.REJECT,
    confidence=lambda values: values.value_rejected,
    reasoning=_value_rejection_reasoning,
)
def value_rejection(context: DecisionContext) -> bool:
    rejection = context.observation.value_rejection
    return (
        rejection is not None
        and rejection.kind not in {
            RejectionKind.PLACEHOLDER,
            RejectionKind.STRUCTURAL_PEM,
            RejectionKind.STRUCTURAL_VALUE,
            RejectionKind.PUBLIC_CRYPTO,
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
    priority=1790,
    disposition=Disposition.REVIEW,
    reasoning="inferred identifier context with secret-target evidence",
)
def context_reject_with_target(context: DecisionContext) -> bool:
    return (
        context.has_identifier_context
        and not context.has_explicit_identifier_context
        and not context.has_credential_context
        and context.has_target_context
    )


@rules.when(
    priority=1780,
    disposition=Disposition.REJECT,
    reasoning="non-secret identifier context",
)
def context_reject(context: DecisionContext) -> bool:
    return (
        context.has_identifier_context
        and not context.has_credential_context
        and (
            context.has_explicit_identifier_context
            or not context.has_target_context
        )
    )


@rules.when(
    priority=2515,
    disposition=Disposition.REPORT,
    confidence=lambda values: values.credential_with_hash_shaped_value,
    reasoning="credential evidence with hash-shaped value",
)
def hash_shaped_key_assignment(context: DecisionContext) -> bool:
    rejection = context.observation.value_rejection
    return (
        (
            context.has_fact(FactId.HASH_SHAPED_VALUE)
            or (
                rejection is not None
                and rejection.kind is RejectionKind.HASH
            )
        )
        and context.groups.matched(
            (ConceptId.KEY_CREDENTIAL,),
            strong_only=False,
        )
        and not context.has_strong_direct_credential_evidence
        and not context.has_fact(FactId.TERMINAL_IDENTIFIER_SUFFIX)
        and "public" not in context.observation.name_tokens
        and not context.groups.matched(
            context.groups.artifacts + context.groups.identifiers
        )
        and not context.groups.matched(
            context.groups.ordinary,
            strong_only=False,
        )
    )


RULES = rules.freeze()
