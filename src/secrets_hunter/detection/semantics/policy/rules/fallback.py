from secrets_hunter.models import Disposition

from .context import DecisionContext
from .models import DecisionPhase
from .rule_set import RuleSet

rules = RuleSet(DecisionPhase.FALLBACK)


@rules.when(
    priority=0,
    disposition=Disposition.REJECT,
    reasoning="no actionable secret classification",
)
def default(context: DecisionContext) -> bool:
    return True


RULES = rules.freeze()
