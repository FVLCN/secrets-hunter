from secrets_hunter.models.fact import Fact
from secrets_hunter.models.semantic_analysis import (
    SemanticAnalysisResult,
    SemanticConceptResult,
    SemanticKeywordEvidenceResult,
    SemanticProviderMatchResult,
)

from .models import (
    ConceptKeywordEvidence,
    ResolvedConcept,
    ProviderMatch,
)


def _keyword_result(
    evidence: ConceptKeywordEvidence,
) -> SemanticKeywordEvidenceResult:
    provider = evidence.provider
    return SemanticKeywordEvidenceResult(
        term=evidence.term,
        source=evidence.source.value,
        strength=evidence.strength.value,
        display_term=evidence.display_term,
        provider_id=provider.id if provider is not None else None,
        provider_name=provider.name if provider is not None else None,
        provider_kind=provider.kind if provider is not None else None,
    )


def build_semantic_analysis_result(
    *,
    concepts: tuple[ResolvedConcept, ...],
    providers: tuple[ProviderMatch, ...],
    facts: tuple[Fact, ...],
) -> SemanticAnalysisResult:
    provider_facts = tuple(
        Fact(
            name="known_provider",
            display_name="Known provider",
            evidence=provider.name,
            source="provider_pattern",
            details={
                "provider_id": provider.id,
                "provider_pattern_id": provider.matched_pattern_id,
                "provider_pattern_classification": (
                    provider.classification.value
                    if provider.classification is not None
                    else "secret"
                ),
            },
        )
        for provider in providers
        if provider.matched_pattern_id is not None
    )
    return SemanticAnalysisResult(
        concepts=tuple(
            SemanticConceptResult(
                concept_id=concept.concept_id.value,
                probability=concept.probability,
                origin=concept.origin,
                strength=concept.strength.value,
                strongest_keywords=tuple(
                    _keyword_result(keyword)
                    for keyword in concept.strongest_keywords
                ),
            )
            for concept in concepts
        ),
        providers=tuple(
            SemanticProviderMatchResult(
                id=provider.id,
                name=provider.name,
                kind=provider.kind,
                target_concept_id=provider.target_concept_id.value,
                strongest_keywords=tuple(
                    _keyword_result(keyword)
                    for keyword in provider.strongest_keywords
                ),
                matched_pattern_id=provider.matched_pattern_id,
                classification=(
                    provider.classification.value
                    if provider.classification is not None
                    else None
                ),
            )
            for provider in providers
        ),
        facts=tuple(sorted((*facts, *provider_facts), key=lambda fact: fact.name)),
    )
