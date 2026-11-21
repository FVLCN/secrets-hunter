from secrets_hunter.models.fact import Fact
from secrets_hunter.models.semantic_analysis import (
    SemanticAnalysisResult,
    SemanticConceptResult,
    SemanticKeywordEvidenceResult,
    SemanticProviderMatchResult,
)
from secrets_hunter.models.rejection import RejectionReason

from ..observation.facts import FactId, make_fact
from .models import (
    ConceptKeywordEvidence,
    ResolvedConcept,
    ProviderMatch,
)


def _known_provider_fact(
    *,
    provider_id: str,
    provider_name: str,
    provider_pattern_id: str,
    provider_pattern_classification: str,
) -> Fact:
    return Fact(
        name="known_provider",
        display_name="Known provider",
        evidence=provider_name,
        source="provider_pattern",
        details={
            "provider_id": provider_id,
            "provider_pattern_id": provider_pattern_id,
            "provider_pattern_classification": provider_pattern_classification,
        },
    )


def _provider_pattern_rejection_facts(
    rejection: RejectionReason | None,
) -> tuple[Fact, ...]:
    if rejection is None or rejection.provider_pattern is None:
        return ()

    provider_pattern = rejection.provider_pattern
    facts = [make_fact(
        FactId.KNOWN_PATTERN_MATCH,
        provider_pattern.pattern_name,
        details={"finding_kind": rejection.name},
    )]

    if (
        provider_pattern.provider_id is not None
        and provider_pattern.provider_name is not None
    ):
        facts.append(_known_provider_fact(
            provider_id=provider_pattern.provider_id,
            provider_name=provider_pattern.provider_name,
            provider_pattern_id=rejection.name,
            provider_pattern_classification=provider_pattern.classification,
        ))

    return tuple(facts)


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
    value_rejection: RejectionReason | None = None,
) -> SemanticAnalysisResult:
    provider_facts = tuple(
        _known_provider_fact(
            provider_id=provider.id,
            provider_name=provider.name,
            provider_pattern_id=provider.matched_pattern_id,
            provider_pattern_classification=(
                provider.classification.value
                if provider.classification is not None
                else "secret"
            ),
        )
        for provider in providers
        if provider.matched_pattern_id is not None
    )
    rejection_facts = _provider_pattern_rejection_facts(value_rejection)
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
        facts=tuple(sorted(
            (*facts, *provider_facts, *rejection_facts),
            key=lambda fact: fact.name,
        )),
    )
