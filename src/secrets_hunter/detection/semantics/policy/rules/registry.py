from collections import Counter
from dataclasses import dataclass
from typing import Self

from .classifications import RULES as CLASSIFICATION_RULES
from .entropy import RULES as ENTROPY_RULES
from .fallback import RULES as FALLBACK_RULES
from .fixtures import RULES as FIXTURE_RULES
from .known_patterns import RULES as KNOWN_PATTERN_RULES
from .models import DecisionPhase, DecisionRule
from .rejections import RULES as REJECTION_RULES
from .structural import RULES as STRUCTURAL_RULES


@dataclass(frozen=True)
class RuleRegistry:
    rules: tuple[DecisionRule, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "rules", self._validated(self.rules))

    @classmethod
    def compose(
        cls,
        *rule_sets: tuple[DecisionRule, ...],
    ) -> Self:
        return cls(tuple(
            rule
            for rule_set in rule_sets
            for rule in rule_set
        ))

    @staticmethod
    def _validated(
        rules: tuple[DecisionRule, ...],
    ) -> tuple[DecisionRule, ...]:
        if not rules:
            raise ValueError("Decision rule registry must not be empty")

        duplicate_ids = sorted(
            rule_id
            for rule_id, count in Counter(
                rule.rule_id
                for rule in rules
            ).items()
            if count > 1
        )

        if duplicate_ids:
            raise ValueError(
                "Duplicate decision rule ids: " + ", ".join(duplicate_ids)
            )

        duplicate_coordinates = sorted(
            coordinate
            for coordinate, count in Counter(
                (rule.phase, rule.priority)
                for rule in rules
            ).items()
            if count > 1
        )

        if duplicate_coordinates:
            formatted = ", ".join(
                f"{phase.name.lower()}:{priority}"
                for phase, priority in duplicate_coordinates
            )
            raise ValueError(f"Duplicate decision rule priorities: {formatted}")

        fallbacks = tuple(
            rule
            for rule in rules
            if rule.phase is DecisionPhase.FALLBACK
        )

        if len(fallbacks) != 1:
            raise ValueError(
                "Decision rule registry must contain exactly one fallback"
            )

        if fallbacks[0].priority != 0:
            raise ValueError("Fallback decision rule priority must be zero")

        return tuple(sorted(
            rules,
            key=lambda rule: rule.precedence,
            reverse=True,
        ))


DEFAULT_REGISTRY = RuleRegistry.compose(
    STRUCTURAL_RULES,
    KNOWN_PATTERN_RULES,
    FIXTURE_RULES,
    REJECTION_RULES,
    ENTROPY_RULES,
    CLASSIFICATION_RULES,
    FALLBACK_RULES,
)
