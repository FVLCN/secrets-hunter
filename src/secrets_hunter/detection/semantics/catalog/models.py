from collections.abc import Mapping
from dataclasses import dataclass, field

from secrets_hunter.detection.semantics.evidence_sources import EvidenceSource
from secrets_hunter.detection.semantics.tokenization import split_identifier
from secrets_hunter.immutability import frozen_mapping

from .policy import SemanticPolicyConfig
from .taxonomy import ConceptCategory, ConceptId, ConceptPolicy


@dataclass(frozen=True)
class SemanticEvidenceRule:
    sources: tuple[EvidenceSource, ...]
    terms: tuple[str, ...] = ()
    phrases: tuple[tuple[str, ...], ...] = ()


@dataclass(frozen=True)
class SemanticConcept:
    id: ConceptId
    category: ConceptCategory
    evidence: tuple[SemanticEvidenceRule, ...]
    policy: ConceptPolicy


@dataclass(frozen=True)
class Provider:
    id: str
    name: str
    kind: str
    target_concept_id: ConceptId
    terms: tuple[str, ...]


@dataclass(frozen=True)
class ProviderPattern:
    id: str
    provider_id: str
    name: str
    regex: str


@dataclass(frozen=True)
class SemanticCatalog:
    concepts: tuple[SemanticConcept, ...]
    compact_aliases: Mapping[str, tuple[str, ...]]
    policy: SemanticPolicyConfig
    providers: tuple[Provider, ...] = ()
    provider_patterns: tuple[ProviderPattern, ...] = ()
    vocabulary: frozenset[str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        compact_aliases = frozen_mapping({
            compact: tuple(aliases)
            for compact, aliases in self.compact_aliases.items()
        })
        object.__setattr__(
            self,
            "compact_aliases",
            compact_aliases
        )
        object.__setattr__(
            self,
            "vocabulary",
            _build_vocabulary(
                self.concepts,
                self.providers,
                compact_aliases
            )
        )

    @property
    def concept_ids(self) -> tuple[ConceptId, ...]:
        return tuple(concept.id for concept in self.concepts)

    def tokens_for_name(self, name: str) -> tuple[str, ...]:
        tokens: list[str] = []

        for token in split_identifier(name):
            alias = self.compact_aliases.get(token)

            if alias:
                tokens.extend(alias)
            else:
                tokens.append(token)

        return tuple(tokens)


def _build_vocabulary(
    concepts: tuple[SemanticConcept, ...],
    providers: tuple[Provider, ...],
    compact_aliases: Mapping[str, tuple[str, ...]]
) -> frozenset[str]:
    terms: set[str] = set()

    for concept in concepts:
        for rule in concept.evidence:
            terms.update(rule.terms)

            for phrase in rule.phrases:
                terms.update(phrase)

    for provider in providers:
        terms.update(provider.terms)

    terms.update(compact_aliases)

    for alias_terms in compact_aliases.values():
        terms.update(alias_terms)

    return frozenset(terms)
