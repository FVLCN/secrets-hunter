from secrets_hunter.detection.semantics.catalog import (
    EvidenceStrength,
)

from .concept_groups import PolicyConceptGroups
from .models import ResolvedConcept


class PolicyPresentation:
    def __init__(
        self,
        *,
        report_probability_threshold: float,
        report_limit: int,
    ) -> None:
        self.report_probability_threshold = report_probability_threshold
        self.report_limit = report_limit

    def reported_concepts(
        self,
        groups: PolicyConceptGroups,
    ) -> tuple[ResolvedConcept, ...]:
        matched = sorted(
            (c for c in groups.concepts.values() if c.origin == "evidence"),
            key=lambda c: (
                c.strength is not EvidenceStrength.STRONG,
                c.concept_id,
            ),
        )
        inferred = sorted(
            (
                c for c in groups.concepts.values()
                if c.origin == "model"
                and c.probability is not None
                and c.probability >= self.report_probability_threshold
            ),
            key=lambda c: (-(c.probability or 0.0), c.concept_id),
        )
        return tuple(matched + inferred[:self.report_limit])
