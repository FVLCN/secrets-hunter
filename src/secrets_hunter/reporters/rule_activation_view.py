from dataclasses import dataclass
from typing import Self

from secrets_hunter.models import Disposition, RuleActivation


@dataclass(frozen=True)
class RuleActivationView:
    rule_id: str
    phase: str
    priority: int
    disposition: Disposition
    confidence: float
    reasoning: str
    selected: bool

    @classmethod
    def from_activation(
        cls,
        activation: RuleActivation,
    ) -> Self:
        return cls(
            rule_id=activation.rule_id,
            phase=activation.phase,
            priority=activation.priority,
            disposition=activation.disposition,
            confidence=activation.confidence,
            reasoning=activation.reasoning,
            selected=activation.selected,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "phase": self.phase,
            "priority": self.priority,
            "disposition": self.disposition.value,
            "confidence": round(self.confidence, 4),
            "reasoning": self.reasoning,
            "selected": self.selected,
        }
