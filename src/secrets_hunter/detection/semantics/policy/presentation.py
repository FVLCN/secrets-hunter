from secrets_hunter.detection.semantics.catalog import ConceptId, SemanticCatalog
from secrets_hunter.detection.semantics.evidence_sources import EvidenceSource

from .concept_groups import PolicyConceptGroups
from .indexes import PolicyIndexes
from .models import ConceptKeywordEvidence, ConceptProbability
from .signals import has_rejection_pattern_evidence, has_value_shape_evidence


class PolicyPresentation:
    def __init__(
        self,
        catalog: SemanticCatalog,
        indexes: PolicyIndexes,
        *,
        report_probability_threshold: float,
        report_limit: int
    ) -> None:
        self._concepts_by_id = indexes.concepts_by_id
        self.report_probability_threshold = report_probability_threshold
        self.report_limit = report_limit

    def reported_concepts(
        self,
        groups: PolicyConceptGroups,
        evidence_by_concept: dict[ConceptId, tuple[ConceptKeywordEvidence, ...]]
    ) -> tuple[ConceptProbability, ...]:
        ranked = sorted(
            (
                (concept_id, probability)
                for concept_id, probability in groups.probabilities.items()
                if probability >= self.report_probability_threshold
                and concept_id in self._concepts_by_id
            ),
            key=lambda item: (-item[1], item[0])
        )

        return tuple(
            ConceptProbability(
                concept_id=concept_id,
                probability=probability,
                strongest_keywords=self._display_evidence(
                    concept_id,
                    evidence_by_concept.get(concept_id, ())
                ),
                display_name=self._display_name(
                    concept_id,
                    evidence_by_concept.get(concept_id, ())
                )
            )
            for concept_id, probability in ranked[:self.report_limit]
        )

    @staticmethod
    def _display_name(
        concept_id: ConceptId,
        evidence: tuple[ConceptKeywordEvidence, ...]
    ) -> str:
        if (
            concept_id is ConceptId.HASH_ARTIFACT
            and (
                has_rejection_pattern_evidence(evidence)
                or has_value_shape_evidence(evidence)
            )
        ):
            return "hash_shaped_value"

        return concept_id.value

    @staticmethod
    def _display_evidence(
        concept_id: ConceptId,
        evidence: tuple[ConceptKeywordEvidence, ...]
    ) -> tuple[ConceptKeywordEvidence, ...]:
        if concept_id is ConceptId.HASH_ARTIFACT and has_value_shape_evidence(evidence):
            return tuple(
                keyword
                for keyword in evidence
                if keyword.source is EvidenceSource.VALUE_SHAPE
            )

        return evidence
