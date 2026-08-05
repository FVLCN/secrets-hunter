from secrets_hunter.detection.semantics.observation import FactId
from secrets_hunter.models.semantic_analysis import (
    SemanticAnalysisResult,
    SemanticConceptResult,
    SemanticKeywordEvidenceResult,
    SemanticProviderMatchResult,
)

from .models import (
    ConceptKeywordEvidence,
    ConceptProbability,
    ProviderMatch,
)


def _keyword_result(
    evidence: ConceptKeywordEvidence,
) -> SemanticKeywordEvidenceResult:
    provider = evidence.provider
    return SemanticKeywordEvidenceResult(
        term=evidence.term,
        source=evidence.source.value,
        display_term=evidence.display_term,
        provider_id=provider.id if provider is not None else None,
        provider_name=provider.name if provider is not None else None,
        provider_kind=provider.kind if provider is not None else None,
    )


def build_semantic_analysis_result(
    *,
    concepts: tuple[ConceptProbability, ...],
    providers: tuple[ProviderMatch, ...],
    facts: tuple[FactId, ...],
) -> SemanticAnalysisResult:
    return SemanticAnalysisResult(
        concepts=tuple(
            SemanticConceptResult(
                concept_id=concept.concept_id.value,
                probability=concept.probability,
                strongest_keywords=tuple(
                    _keyword_result(keyword)
                    for keyword in concept.strongest_keywords
                ),
                display_name=concept.display_name
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
            )
            for provider in providers
        ),
        facts=tuple(fact.value for fact in facts),
    )
