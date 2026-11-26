from collections.abc import Callable
from dataclasses import fields
from functools import wraps

from secrets_hunter.detection.semantics.catalog.policy import ConfidencePolicy
from secrets_hunter.models import Disposition

from .context import DecisionContext
from .models import DecisionPhase, DecisionRule, RuleOutcome

type RulePredicate = Callable[[DecisionContext], bool]
type ReasoningResolver = Callable[[DecisionContext], str]
type ConfidenceResolver = Callable[[ConfidencePolicy], float]
type Reasoning = str | ReasoningResolver

_CONFIDENCE_FIELDS = frozenset(
    field.name
    for field in fields(ConfidencePolicy)
)
_CONFIDENCE_PROBE = ConfidencePolicy(**{
    field_name: 0.0
    for field_name in _CONFIDENCE_FIELDS
})


def _confidence_for_rule(rule_id: str) -> ConfidenceResolver:
    if rule_id not in _CONFIDENCE_FIELDS:
        raise ValueError(
            f"Rule {rule_id!r} requires an explicit confidence resolver"
        )

    def resolve(confidence: ConfidencePolicy) -> float:
        return getattr(confidence, rule_id)

    return resolve


def _validated_confidence_resolver(
    rule_id: str,
    resolve: ConfidenceResolver,
) -> ConfidenceResolver:
    try:
        resolved = resolve(_CONFIDENCE_PROBE)
    except AttributeError as error:
        raise ValueError(
            f"Invalid confidence resolver for rule {rule_id!r}"
        ) from error

    if not isinstance(resolved, float):
        raise TypeError(
            f"Confidence resolver for rule {rule_id!r} must return a float"
        )

    if not 0.0 <= resolved <= 1.0:
        raise ValueError(
            f"Confidence resolver for rule {rule_id!r} must return a probability"
        )

    return resolve


class RuleSet:
    def __init__(self, phase: DecisionPhase) -> None:
        self._phase = phase
        self._rules: list[DecisionRule] = []
        self._frozen_rules: tuple[DecisionRule, ...] | None = None

    def freeze(self) -> tuple[DecisionRule, ...]:
        if self._frozen_rules is None:
            self._frozen_rules = tuple(self._rules)

        return self._frozen_rules

    def when(
        self,
        *,
        priority: int,
        disposition: Disposition,
        reasoning: Reasoning,
        confidence: ConfidenceResolver | None = None,
    ) -> Callable[[RulePredicate], RulePredicate]:
        if self._frozen_rules is not None:
            raise RuntimeError("Cannot register a rule after freezing its rule set")

        def register(predicate: RulePredicate) -> RulePredicate:
            if self._frozen_rules is not None:
                raise RuntimeError(
                    "Cannot register a rule after freezing its rule set"
                )

            rule_id = predicate.__name__.removeprefix("_")
            resolve_confidence = _validated_confidence_resolver(
                rule_id,
                confidence or _confidence_for_rule(rule_id),
            )

            @wraps(predicate)
            def evaluate(context: DecisionContext) -> RuleOutcome | None:
                if not predicate(context):
                    return None

                resolved_reasoning = (
                    reasoning(context)
                    if callable(reasoning)
                    else reasoning
                )
                return RuleOutcome(
                    disposition=disposition,
                    confidence=resolve_confidence(context.policy.confidence),
                    reasoning=resolved_reasoning,
                )

            self._rules.append(DecisionRule(
                rule_id=rule_id,
                phase=self._phase,
                priority=priority,
                evaluate=evaluate,
            ))
            return predicate

        return register
