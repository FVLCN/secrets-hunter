from collections.abc import Iterable

from secrets_hunter.detection.semantics.catalog import (
    ConceptId,
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
    def _keyword_evidence(
        term: str,
        source: EvidenceSource
    ) -> ConceptKeywordEvidence:
        return ConceptKeywordEvidence(
            term=term,
            source=source
        )

    @staticmethod
    def _rank_evidence(
        evidence: Iterable[ConceptKeywordEvidence],
        limit: int | None
    ) -> tuple[ConceptKeywordEvidence, ...]:
        return tuple(sorted(
            dict.fromkeys(evidence),
            key=lambda keyword: (
                evidence_source_priority(keyword.source),
                -len(keyword.term.split("_")),
                keyword.term,
                keyword.provider.id if keyword.provider else ""
            )
        )[:limit])

    def _keyword_evidence_for_concept(
        self,
        concept: SemanticConcept,
        tokens_by_source: dict[EvidenceSource, tuple[str, ...]],
        observation: SemanticObservation,
        *,
        limit: int = 3
    ) -> tuple[ConceptKeywordEvidence, ...]:
        evidence: dict[str, ConceptKeywordEvidence] = {}
        value_rejection = observation.value_rejection

        if concept.id is ConceptId.ORDINARY_IDENTIFIER_WORDS:
            for token in observation.neutral_identifier_tokens:
                evidence[token] = ConceptKeywordEvidence(
                    term=token,
                    source=EvidenceSource.VAR_NAME
                )

        if (
            concept.id is ConceptId.PLACEHOLDER_VALUE
            and value_rejection is not None
            and value_rejection.kind is RejectionKind.PLACEHOLDER
        ):
            evidence[value_rejection.name] = ConceptKeywordEvidence(
                term=value_rejection.name,
                source=EvidenceSource.REJECTION_PATTERN
            )

        for source, tokens in tokens_by_source.items():
            for rule in concept.evidence:
                if source not in rule.sources:
                    continue

                for phrase in rule.phrases:
                    term = "_".join(phrase)

                    if contains_phrase(tokens, phrase):
                        evidence.setdefault(
                            term,
                            self._keyword_evidence(
                                term=term,
                                source=source
                            )
                        )

                for term in rule.terms:
                    if term in tokens:
                        if (
                            concept.id is ConceptId.PLACEHOLDER_VALUE
                            and term == "placeholder"
                            and value_rejection is not None
                            and value_rejection.kind is RejectionKind.PLACEHOLDER
                        ):
                            continue

                        existing = evidence.get(term)

                        if (
                            existing
                            and evidence_source_priority(existing.source)
                            <= evidence_source_priority(source)
                        ):
                            continue

                        evidence[term] = self._keyword_evidence(
                            term=term,
                            source=source
                        )

        return self._rank_evidence(evidence.values(), limit)

    def collect(
        self,
        tokens_by_source: dict[EvidenceSource, tuple[str, ...]],
        observation: SemanticObservation,
        *,
        provider_matches: tuple[ProviderMatch, ...]
    ) -> dict[ConceptId, tuple[ConceptKeywordEvidence, ...]]:
        evidence_by_concept = {
            concept.id: self._keyword_evidence_for_concept(
                concept,
                tokens_by_source,
                observation
            )
            for concept in self.catalog.concepts
        }

        for provider_match in provider_matches:
            target_concept_id = provider_match.target_concept_id
            evidence_by_concept[target_concept_id] = self._rank_evidence(
                (
                    *evidence_by_concept.get(target_concept_id, ()),
                    *provider_match.strongest_keywords,
                ),
                3
            )

        return evidence_by_concept
