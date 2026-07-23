from secrets_hunter.detection.semantics.observation import FactId
from secrets_hunter.models import Disposition

from .context import DecisionContext
from .models import DecisionPhase
from .rule_set import RuleSet

rules = RuleSet(DecisionPhase.KNOWN_PATTERN)


@rules.when(
    priority=200,
    disposition=Disposition.REPORT,
    confidence=lambda values: values.strong_secret_pattern,
    reasoning="known secret pattern with strong secret classification",
)
def known_pattern_strong_context(context: DecisionContext) -> bool:
    return (
        context.has_fact(FactId.KNOWN_PATTERN_MATCH)
        and context.strong_secret_context
    )


@rules.when(
    priority=100,
    disposition=Disposition.REPORT,
    confidence=lambda values: values.known_pattern,
    reasoning="known secret pattern match",
)
def known_pattern_match(context: DecisionContext) -> bool:
    return (
        context.has_fact(FactId.KNOWN_PATTERN_MATCH)
        and not context.strong_secret_context
    )


RULES = rules.freeze()
