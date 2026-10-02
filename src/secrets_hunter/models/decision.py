from dataclasses import dataclass
from enum import StrEnum


class Disposition(StrEnum):
    REPORT = "report"
    REVIEW = "review"
    REJECT = "reject"


@dataclass(frozen=True)
class RuleActivation:
    rule_id: str
    phase: str
    priority: int
    disposition: Disposition
    confidence: float
    reasoning: str
    selected: bool

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("Rule confidence must be between 0 and 1")

        if not self.phase:
            raise ValueError("Rule phase must not be empty")

        if self.priority < 0:
            raise ValueError("Rule priority must not be negative")

@dataclass(frozen=True)
class Decision:
    trace: tuple[RuleActivation, ...]

    def __post_init__(self) -> None:
        selected = tuple(
            activation
            for activation in self.trace
            if activation.selected
        )

        if len(selected) != 1:
            raise ValueError("Decision trace must contain exactly one selected rule")

    @property
    def selected_rule(self) -> RuleActivation:
        return next(
            activation
            for activation in self.trace
            if activation.selected
        )

    @property
    def confidence(self) -> float:
        return self.selected_rule.confidence

    @property
    def disposition(self) -> Disposition:
        return self.selected_rule.disposition

    @property
    def reasoning(self) -> str:
        return self.selected_rule.reasoning
