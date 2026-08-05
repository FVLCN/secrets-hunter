from collections.abc import Callable
from dataclasses import dataclass
from enum import IntEnum

from secrets_hunter.models import Disposition

from .context import DecisionContext


class DecisionPhase(IntEnum):
    FALLBACK = 0
    SEMANTIC = 100
    KNOWN_PATTERN = 200
    STRUCTURAL = 300


@dataclass(frozen=True)
class RuleOutcome:
    disposition: Disposition
    confidence: float
    reasoning: str

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("Rule confidence must be between 0 and 1")

        if not self.reasoning:
            raise ValueError("Rule reasoning must not be empty")


type RuleEvaluator = Callable[[DecisionContext], RuleOutcome | None]


@dataclass(frozen=True)
class DecisionRule:
    rule_id: str
    phase: DecisionPhase
    priority: int
    evaluate: RuleEvaluator

    def __post_init__(self) -> None:
        if not self.rule_id:
            raise ValueError("Decision rule id must not be empty")

        if not isinstance(self.phase, DecisionPhase):
            raise TypeError("Decision rule phase must be a DecisionPhase")

        if self.priority < 0:
            raise ValueError("Decision rule priority must not be negative")

    @property
    def precedence(self) -> tuple[int, int]:
        return int(self.phase), self.priority
