from collections import Counter
from collections.abc import Iterable

from .models import Provider, ProviderPattern, SemanticConcept, SemanticEvidenceRule
from .taxonomy import ConceptId


def require_unique_ids(
    item_ids: Iterable[str],
    entity: str,
    source: str
) -> None:
    duplicates = sorted(
        item_id
        for item_id, count in Counter(item_ids).items()
        if count > 1
    )

    if duplicates:
        raise ValueError(f"Duplicate {entity} ids in {source}: {', '.join(duplicates)}")


def _validate_evidence_references(
    evidence_by_concept: dict[ConceptId, tuple[SemanticEvidenceRule, ...]],
    concepts: tuple[SemanticConcept, ...],
    source: str
) -> None:
    concept_ids = {concept.id for concept in concepts}
    unknown = sorted(set(evidence_by_concept) - concept_ids)

    if unknown:
        raise ValueError(f"Evidence in {source} references unknown concepts: {', '.join(unknown)}")


def _validate_provider_references(providers: tuple[Provider, ...], concepts: tuple[SemanticConcept, ...], source: str) -> None:
    concept_ids = {concept.id for concept in concepts}
    unknown = sorted({
        provider.target_concept
        for provider in providers
        if provider.target_concept not in concept_ids
    })

    if unknown:
        raise ValueError(f"Providers in {source} reference unknown target concepts: {', '.join(unknown)}")


def _validate_provider_kind_targets(
    provider_kind_targets: dict[str, ConceptId],
    concepts: tuple[SemanticConcept, ...],
    source: str
) -> None:
    concept_ids = {concept.id for concept in concepts}
    unknown = sorted(set(provider_kind_targets.values()) - concept_ids)

    if unknown:
        raise ValueError(f"Provider kind targets in {source} reference unknown concepts: {', '.join(unknown)}")


def _validate_provider_pattern_references(
    provider_patterns: tuple[ProviderPattern, ...],
    providers: tuple[Provider, ...],
    source: str
) -> None:
    provider_ids = {provider.id for provider in providers}
    unknown = sorted({
        pattern.provider_id
        for pattern in provider_patterns
        if pattern.provider_id not in provider_ids
    })

    if unknown:
        raise ValueError(f"Provider patterns in {source} reference unknown providers: {', '.join(unknown)}")
