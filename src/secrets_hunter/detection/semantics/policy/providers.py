from secrets_hunter.detection.semantics.catalog import Provider, SemanticCatalog
from secrets_hunter.detection.semantics.evidence_sources import (
    EvidenceSource,
    evidence_source_priority,
    provider_matchable_evidence_sources,
)
from secrets_hunter.detection.semantics.observation.models import SemanticObservation

from .models import (
    ConceptKeywordEvidence,
    ProviderMatch,
)


def provider_evidence_for_pattern(
    provider: Provider
) -> ConceptKeywordEvidence:
    return ConceptKeywordEvidence(
        term=provider.id,
        source=EvidenceSource.PROVIDER_PATTERN,
        display_term=f"provider: {provider.name}",
        provider=provider
    )


class ProviderMatcher:
    def __init__(self, catalog: SemanticCatalog) -> None:
        self.catalog = catalog
        self.provider_patterns_by_id = {
            pattern.id: pattern
            for pattern in catalog.provider_patterns
        }

    def _provider_evidence(
        self,
        provider: Provider,
        tokens_by_source: dict[EvidenceSource, tuple[str, ...]]
    ) -> tuple[ConceptKeywordEvidence, ...]:
        evidence: dict[tuple[EvidenceSource, str], ConceptKeywordEvidence] = {}

        for source in provider_matchable_evidence_sources():
            tokens = tokens_by_source.get(source, ())

            for term in provider.terms:
                if term in tokens:
                    evidence[(source, term)] = ConceptKeywordEvidence(
                        term=term,
                        source=source,
                        display_term=f"provider: {provider.name}",
                        provider=provider
                    )

        return tuple(sorted(
            evidence.values(),
            key=lambda keyword: (
                evidence_source_priority(keyword.source),
                keyword.term
            )
        ))

    def matches(
        self,
        tokens_by_source: dict[EvidenceSource, tuple[str, ...]],
        observation: SemanticObservation
    ) -> tuple[ProviderMatch, ...]:
        matches_by_id: dict[str, ProviderMatch] = {}
        matched_pattern = self.provider_patterns_by_id.get(
            observation.provider_pattern_id
        )

        for provider in self.catalog.providers:
            evidence = list(self._provider_evidence(provider, tokens_by_source))
            matched_pattern_id = None

            if matched_pattern is not None and provider.id == matched_pattern.provider_id:
                evidence.append(provider_evidence_for_pattern(provider))
                matched_pattern_id = matched_pattern.id

            if not evidence:
                continue

            matches_by_id[provider.id] = (
                ProviderMatch(
                    provider=provider,
                    strongest_keywords=tuple(sorted(
                        dict.fromkeys(evidence),
                        key=lambda keyword: (
                            evidence_source_priority(keyword.source),
                            keyword.term
                        )
                    )),
                    matched_pattern_id=matched_pattern_id
                )
            )

        return tuple(sorted(
            matches_by_id.values(),
            key=lambda provider: (
                evidence_source_priority(provider.strongest_keywords[0].source),
                provider.name.lower(),
                provider.id
            )
        ))
