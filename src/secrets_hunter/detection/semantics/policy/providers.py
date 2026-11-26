from dataclasses import replace

from secrets_hunter.detection.semantics.catalog import (
    EvidenceStrength,
    Provider,
    SemanticCatalog,
)
from secrets_hunter.detection.semantics.evidence_sources import (
    EvidenceSource,
    evidence_source_priority,
    provider_matchable_evidence_sources,
)
from secrets_hunter.detection.semantics.observation.models import SemanticObservation
from secrets_hunter.detection.semantics.tokenization import split_identifier

from .models import ConceptKeywordEvidence, ProviderMatch


def provider_evidence_for_pattern(provider: Provider) -> ConceptKeywordEvidence:
    return ConceptKeywordEvidence(
        term=provider.id,
        source=EvidenceSource.PROVIDER_PATTERN,
        display_term=f"provider: {provider.name}",
        provider=provider,
    )


def _contains_provider_term(tokens: tuple[str, ...], term: str) -> bool:
    compact = "".join(split_identifier(term))
    if not compact:
        return False
    for start in range(len(tokens)):
        candidate = ""
        for index in range(start, len(tokens)):
            candidate += tokens[index]
            if candidate == compact:
                return True
            if not compact.startswith(candidate):
                break
    return False


class ProviderMatcher:
    def __init__(self, catalog: SemanticCatalog) -> None:
        self.catalog = catalog
        self.provider_patterns_by_id = {
            pattern.id: pattern for pattern in catalog.provider_patterns
        }

    def _provider_evidence(
        self,
        provider: Provider,
        tokens_by_source: dict[EvidenceSource, tuple[str, ...]],
    ) -> tuple[ConceptKeywordEvidence, ...]:
        evidence: list[ConceptKeywordEvidence] = []
        for source in provider_matchable_evidence_sources():
            tokens = tokens_by_source.get(source, ())
            for term in provider.terms:
                if _contains_provider_term(tokens, term):
                    evidence.append(ConceptKeywordEvidence(
                        term=term,
                        source=source,
                        display_term=f"provider: {provider.name}",
                        provider=provider,
                    ))
        return tuple(sorted(
            dict.fromkeys(evidence),
            key=lambda keyword: (
                evidence_source_priority(keyword.source), keyword.term
            ),
        ))

    def matches(
        self,
        tokens_by_source: dict[EvidenceSource, tuple[str, ...]],
        observation: SemanticObservation,
    ) -> tuple[ProviderMatch, ...]:
        matches: list[ProviderMatch] = []
        matched_pattern = self.provider_patterns_by_id.get(
            observation.provider_pattern_id
        )
        for provider in self.catalog.providers:
            evidence = self._provider_evidence(provider, tokens_by_source)
            matched_pattern_id = None
            classification = None
            if (
                matched_pattern is not None
                and matched_pattern.provider_id is not None
            ):
                if provider.id == matched_pattern.provider_id:
                    evidence = (provider_evidence_for_pattern(provider), *evidence)
                    matched_pattern_id = matched_pattern.id
                    classification = matched_pattern.classification
                else:
                    evidence = tuple(
                        replace(item, strength=EvidenceStrength.WEAK)
                        for item in evidence
                    )
            if evidence:
                matches.append(ProviderMatch(
                    provider=provider,
                    strongest_keywords=evidence,
                    matched_pattern_id=matched_pattern_id,
                    classification=classification,
                ))

        return tuple(sorted(
            matches,
            key=lambda provider: (
                provider.matched_pattern_id is None,
                evidence_source_priority(provider.strongest_keywords[0].source),
                -max(
                    len("".join(split_identifier(e.term)))
                    for e in provider.strongest_keywords
                ),
                provider.name.lower(),
                provider.id,
            ),
        ))
