from collections.abc import Mapping

from secrets_hunter.detection.semantics.parsing import (
    normalize_token,
    require_string_list,
    require_table
)
from secrets_hunter.detection.semantics.evidence_sources import (
    EvidenceSource,
    evidence_source_spec,
)
from secrets_hunter.detection.semantics.tokenization import split_identifier

from .models import SemanticConcept, SemanticEvidenceRule
from .validation import require_unique_ids
from .taxonomy import (
    ConceptId,
    ConceptPolicy,
    require_concept_category,
    require_concept_id,
    require_concept_policy,
)


def _load_concepts(
    data: Mapping[str, object],
    source: str,
    evidence_by_concept: Mapping[ConceptId, tuple[SemanticEvidenceRule, ...]]
) -> tuple[SemanticConcept, ...]:
    raw_concepts = data.get("concepts") or []

    if not isinstance(raw_concepts, list):
        raise ValueError(f"'concepts' must be an array in {source}")

    concepts: list[SemanticConcept] = []

    for raw_concept in raw_concepts:
        concept_data = require_table(raw_concept, "concepts entry", source)

        concept_id = require_concept_id(concept_data.get("id"), "concept id", source)
        category = require_concept_category(concept_data.get("category"), source)
        if any(
            key in concept_data
            for key in ("is_fact", "kind", "trainable")
        ):
            raise ValueError(
                f"Concept {concept_id!r} in {source} cannot be declared as a fact; "
                "use the observation fact taxonomy instead"
            )

        if "terms" in concept_data or "phrases" in concept_data or "evidence" in concept_data:
            raise ValueError(
                f"Concept {concept_id!r} in {source} must define evidence in evidences.toml, "
                "not in concepts.toml"
            )

        if "examples" in concept_data or "training_examples" in concept_data:
            raise ValueError(
                f"Concept {concept_id!r} in {source} must define training examples in "
                "training_examples.toml, not in concepts.toml"
            )

        concepts.append(
            SemanticConcept(
                id=concept_id,
                category=category,
                evidence=evidence_by_concept.get(concept_id, ()),
                policy=require_concept_policy(
                    concept_data.get("policy") or ConceptPolicy.EVIDENCE.value,
                    source
                )
            )
        )

    require_unique_ids(
        (concept.id for concept in concepts),
        "concept",
        source
    )

    return tuple(concepts)


def _load_evidence_rule(
    raw_rule: Mapping[str, object],
    source: str
) -> SemanticEvidenceRule:
    raw_sources = require_string_list(raw_rule, "sources", source)

    if not raw_sources:
        raise ValueError(f"'sources' must not be empty in {source}")

    sources: list[EvidenceSource] = []
    unknown_sources: list[str] = []

    for value in raw_sources:
        normalized = normalize_token(value)

        try:
            evidence_source = EvidenceSource(normalized)
        except ValueError:
            unknown_sources.append(normalized)
            continue

        if not evidence_source_spec(evidence_source).catalog_allowed:
            unknown_sources.append(normalized)
            continue

        sources.append(evidence_source)

    if unknown_sources:
        raise ValueError(
            f"Unknown evidence sources in {source}: "
            f"{', '.join(sorted(set(unknown_sources)))}"
        )

    terms = tuple(
        normalize_token(term)
        for term in require_string_list(raw_rule, "terms", source)
    )
    phrases = tuple(
        split_identifier(phrase)
        for phrase in require_string_list(raw_rule, "phrases", source)
    )

    if not terms and not phrases:
        raise ValueError(f"Evidence rule in {source} must include terms or phrases")

    return SemanticEvidenceRule(
        sources=tuple(dict.fromkeys(sources)),
        terms=tuple(dict.fromkeys(terms)),
        phrases=tuple(dict.fromkeys(phrases))
    )


def _load_evidence_by_concept(
    data: Mapping[str, object],
    source: str
) -> dict[ConceptId, tuple[SemanticEvidenceRule, ...]]:
    raw_rules = data.get("evidence") or []

    if not isinstance(raw_rules, list):
        raise ValueError(f"'evidence' must be an array in {source}")

    evidence_by_concept: dict[ConceptId, list[SemanticEvidenceRule]] = {}

    for raw_value in raw_rules:
        raw_rule = require_table(raw_value, "evidence entry", source)

        concept_id = require_concept_id(
            raw_rule.get("concept"),
            "evidence concept",
            source
        )
        evidence_by_concept.setdefault(concept_id, []).append(_load_evidence_rule(raw_rule, source))

    return {
        concept_id: tuple(rules)
        for concept_id, rules in evidence_by_concept.items()
    }


def _load_explicit_compact_aliases(
    *data_sources: Mapping[str, object]
) -> dict[str, tuple[str, ...]]:
    aliases: dict[str, tuple[str, ...]] = {}

    for data in data_sources:
        raw_aliases = data.get("compact_aliases") or {}

        aliases_table = require_table(
            raw_aliases,
            "compact_aliases",
            "semantic catalogs"
        )

        for compact in aliases_table:
            aliases[normalize_token(compact)] = tuple(
                normalize_token(token)
                for token in require_string_list(
                    aliases_table,
                    compact,
                    "compact_aliases"
                )
            )

    return aliases


def _derive_compact_aliases_from_evidence(
    *evidence_sources: Mapping[ConceptId, tuple[SemanticEvidenceRule, ...]]
) -> dict[str, tuple[str, ...]]:
    aliases: dict[str, tuple[str, ...]] = {}

    for evidence_by_concept in evidence_sources:
        for rules in evidence_by_concept.values():
            for rule in rules:
                for phrase in rule.phrases:
                    if len(phrase) < 2:
                        continue

                    compact = "".join(phrase)
                    aliases.setdefault(compact, phrase)

    return aliases
