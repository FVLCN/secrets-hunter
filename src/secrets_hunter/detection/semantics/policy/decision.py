from dataclasses import dataclass

from secrets_hunter.detection.semantics.catalog import ConceptId, SemanticCatalog
from secrets_hunter.detection.semantics.observation import SemanticObservation
from secrets_hunter.models import Decision, Disposition, RuleActivation

from .concept_groups import PolicyConceptGroups
from .rules import (
    DEFAULT_REGISTRY,
    DecisionContext,
    DecisionPhase,
    DecisionRule,
    RuleRegistry,
    RuleOutcome,
)


@dataclass(frozen=True)
class _RuleMatch:
    rule: DecisionRule
    outcome: RuleOutcome


class SecretDecisionPolicy:
    def __init__(
        self,
        catalog: SemanticCatalog,
        *,
        rules: RuleRegistry | tuple[DecisionRule, ...] = DEFAULT_REGISTRY
    ) -> None:
        self.policy = catalog.policy
        self.registry = (
            rules
            if isinstance(rules, RuleRegistry)
            else RuleRegistry(rules)
        )
        self.rules = self.registry.rules

    def decide(
        self,
        observation: SemanticObservation,
        groups: PolicyConceptGroups,
    ) -> Decision:
        if groups.policy != self.policy:
            raise ValueError("Decision groups use a different semantic policy")

        context = DecisionContext.build(
            observation,
            groups,
        )
        matches: list[_RuleMatch] = []
        fallback: DecisionRule | None = None

        for rule in self.rules:
            if rule.phase is DecisionPhase.FALLBACK:
                fallback = rule
                continue

            outcome = rule.evaluate(context)

            if outcome is not None:
                matches.append(_RuleMatch(rule=rule, outcome=outcome))

        if not matches:
            if fallback is None:
                raise RuntimeError("Validated decision registry lost its fallback rule")

            fallback_outcome = fallback.evaluate(context)

            if fallback_outcome is None:
                raise RuntimeError("Fallback decision rule did not produce an outcome")

            matches.append(_RuleMatch(rule=fallback, outcome=fallback_outcome))

        winner = matches[0]
        fixture_cap: RuleActivation | None = None
        confidence_cap = self.policy.confidence.fixture_confidence_cap
        if (
            groups.matched((ConceptId.TEST_FIXTURE,))
            and winner.outcome.disposition is not Disposition.REJECT
            and (
                winner.outcome.disposition is Disposition.REPORT
                or winner.outcome.confidence > confidence_cap
            )
        ):
            fixture_cap = RuleActivation(
                rule_id="strong_fixture_confidence_cap",
                phase=DecisionPhase.CONSTRAINT.name.lower(),
                priority=0,
                disposition=Disposition.REVIEW,
                confidence=min(winner.outcome.confidence, confidence_cap),
                reasoning="strong fixture evidence",
                selected=True,
            )

        trace = tuple(
            RuleActivation(
                rule_id=match.rule.rule_id,
                phase=match.rule.phase.name.lower(),
                priority=match.rule.priority,
                disposition=match.outcome.disposition,
                confidence=match.outcome.confidence,
                reasoning=match.outcome.reasoning,
                selected=match is winner and fixture_cap is None,
            )
            for match in matches
        )

        if fixture_cap is not None:
            trace = (fixture_cap, *trace)

        return Decision(trace=trace)
