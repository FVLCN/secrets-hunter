from collections.abc import Iterable

from secrets_hunter.detection.semantics.catalog import (
    ConceptId,
    EvidenceStrength,
    SemanticCatalog,
    SemanticConcept,
)
from secrets_hunter.detection.semantics.evidence_sources import (
    EvidenceSource,
    evidence_source_priority,
)
from secrets_hunter.detection.semantics.matching import contains_phrase
from secrets_hunter.detection.semantics.observation.models import SemanticObservation
from secrets_hunter.models import RejectionKind

from .models import ConceptKeywordEvidence, ProviderMatch


class EvidenceCollector:
    def __init__(self, catalog: SemanticCatalog) -> None:
        self.catalog = catalog

    @staticmethod
    def _rank_evidence(
        evidence: Iterable[ConceptKeywordEvidence],
    ) -> tuple[ConceptKeywordEvidence, ...]:
        return tuple(sorted(
            dict.fromkeys(evidence),
            key=lambda keyword: (
                keyword.strength is not EvidenceStrength.STRONG,
                evidence_source_priority(keyword.source),
                -len(keyword.term.split("_")),
                keyword.term,
                keyword.provider.id if keyword.provider else "",
            ),
        ))

    def _keyword_evidence_for_concept(
        self,
        concept: SemanticConcept,
        tokens_by_source: dict[EvidenceSource, tuple[str, ...]],
        observation: SemanticObservation,
    ) -> tuple[ConceptKeywordEvidence, ...]:
        evidence: list[ConceptKeywordEvidence] = []
        value_rejection = observation.value_rejection

        if concept.id is ConceptId.ORDINARY_IDENTIFIER_WORDS:
            evidence.extend(
                ConceptKeywordEvidence(
                    term=token,
                    source=EvidenceSource.VAR_NAME,
                    strength=EvidenceStrength.WEAK,
                )
                for token in observation.neutral_identifier_tokens
            )

        if (
            concept.id is ConceptId.PLACEHOLDER_VALUE
            and value_rejection is not None
            and value_rejection.kind is RejectionKind.PLACEHOLDER
        ):
            evidence.append(ConceptKeywordEvidence(
                term=value_rejection.name,
                source=EvidenceSource.REJECTION_PATTERN,
            ))

        for source, tokens in tokens_by_source.items():
            for rule in concept.evidence:
                if source not in rule.sources:
                    continue

                for phrase in rule.phrases:
                    if contains_phrase(tokens, phrase):
                        evidence.append(ConceptKeywordEvidence(
                            term="_".join(phrase),
                            source=source,
                            strength=rule.strength,
                        ))

                for term in rule.terms:
                    if term not in tokens:
                        continue
                    if (
                        concept.id is ConceptId.PLACEHOLDER_VALUE
                        and term == "placeholder"
                        and value_rejection is not None
                        and value_rejection.kind is RejectionKind.PLACEHOLDER
                    ):
                        continue
                    evidence.append(ConceptKeywordEvidence(
                        term=term,
                        source=source,
                        strength=rule.strength,
                    ))

        return self._rank_evidence(evidence)

    def collect(
        self,
        tokens_by_source: dict[EvidenceSource, tuple[str, ...]],
        observation: SemanticObservation,
        *,
        provider_matches: tuple[ProviderMatch, ...],
    ) -> dict[ConceptId, tuple[ConceptKeywordEvidence, ...]]:
        evidence_by_concept = {
            concept.id: self._keyword_evidence_for_concept(
                concept, tokens_by_source, observation
            )
            for concept in self.catalog.concepts
        }

        for provider_match in provider_matches:
            target_concept_id = provider_match.target_concept_id
            evidence_by_concept[target_concept_id] = self._rank_evidence((
                *evidence_by_concept.get(target_concept_id, ()),
                *provider_match.strongest_keywords,
            ))

        return evidence_by_concept
