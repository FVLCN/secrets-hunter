from pathlib import Path

from secrets_hunter.resources import load_toml

from .concepts import (
    _derive_compact_aliases_from_evidence,
    _load_concepts,
    _load_evidence_by_concept,
    _load_explicit_compact_aliases,
)
from .models import SemanticCatalog
from .policy import _load_policy_config
from .providers import (
    _load_provider_kind_target_ids,
    _load_provider_patterns,
    _load_providers
)
from .sources import (
    NEGATIVE_CONCEPTS_RESOURCE,
    NEGATIVE_EVIDENCE_RESOURCE,
    POLICY_RESOURCE,
    POSITIVE_CONCEPTS_RESOURCE,
    POSITIVE_EVIDENCE_RESOURCE,
    PROVIDER_PATTERNS_RESOURCE,
    PROVIDERS_RESOURCE,
)
from .validation import (
    _validate_evidence_references,
    _validate_provider_kind_target_ids,
    _validate_provider_pattern_references,
    _validate_provider_references,
    require_unique_ids
)


def load_semantic_catalog(
    *,
    secret_catalog_path: str | Path | None = None,
    false_positive_catalog_path: str | Path | None = None,
    secret_evidence_path: str | Path | None = None,
    false_positive_evidence_path: str | Path | None = None,
    providers_path: str | Path | None = None,
    provider_patterns_path: str | Path | None = None,
    policy_path: str | Path | None = None
) -> SemanticCatalog:
    secret_document = load_toml(
        secret_catalog_path,
        fallback_resource=POSITIVE_CONCEPTS_RESOURCE
    )
    false_positive_document = load_toml(
        false_positive_catalog_path,
        fallback_resource=NEGATIVE_CONCEPTS_RESOURCE
    )
    secret_evidence_document = load_toml(
        secret_evidence_path,
        fallback_resource=POSITIVE_EVIDENCE_RESOURCE
    )
    false_positive_evidence_document = load_toml(
        false_positive_evidence_path,
        fallback_resource=NEGATIVE_EVIDENCE_RESOURCE
    )
    providers_document = load_toml(
        providers_path,
        fallback_resource=PROVIDERS_RESOURCE
    )
    provider_patterns_document = load_toml(
        provider_patterns_path,
        fallback_resource=PROVIDER_PATTERNS_RESOURCE
    )
    policy_document = load_toml(
        policy_path,
        fallback_resource=POLICY_RESOURCE
    )
    secret_data, secret_source = secret_document.data, secret_document.source
    false_positive_data = false_positive_document.data
    false_positive_source = false_positive_document.source
    secret_evidence_data = secret_evidence_document.data
    secret_evidence_source = secret_evidence_document.source
    false_positive_evidence_data = false_positive_evidence_document.data
    false_positive_evidence_source = false_positive_evidence_document.source
    providers_data, providers_source = providers_document.data, providers_document.source
    provider_patterns_data = provider_patterns_document.data
    provider_patterns_source = provider_patterns_document.source
    policy_data, policy_source = policy_document.data, policy_document.source
    provider_kind_target_ids = _load_provider_kind_target_ids(
        providers_data,
        providers_source
    )
    providers = _load_providers(
        providers_data,
        providers_source,
        provider_kind_target_ids
    )
    provider_patterns = _load_provider_patterns(provider_patterns_data, provider_patterns_source)
    secret_evidence = _load_evidence_by_concept(secret_evidence_data, secret_evidence_source)
    false_positive_evidence = _load_evidence_by_concept(
        false_positive_evidence_data,
        false_positive_evidence_source
    )
    derived_compact_aliases = _derive_compact_aliases_from_evidence(
        secret_evidence,
        false_positive_evidence
    )
    explicit_compact_aliases = _load_explicit_compact_aliases(secret_data, false_positive_data)
    secret_concepts = _load_concepts(secret_data, secret_source, secret_evidence)
    false_positive_concepts = _load_concepts(
        false_positive_data,
        false_positive_source,
        false_positive_evidence
    )
    _validate_provider_kind_target_ids(
        provider_kind_target_ids,
        secret_concepts,
        providers_source
    )
    _validate_provider_references(providers, secret_concepts, providers_source)
    _validate_provider_pattern_references(provider_patterns, providers, provider_patterns_source)
    _validate_evidence_references(
        secret_evidence,
        secret_concepts,
        secret_evidence_source
    )
    _validate_evidence_references(
        false_positive_evidence,
        false_positive_concepts,
        false_positive_evidence_source
    )
    concepts = secret_concepts + false_positive_concepts
    require_unique_ids(
        (concept.id for concept in concepts),
        "concept",
        "semantic catalogs"
    )

    return SemanticCatalog(
        concepts=concepts,
        compact_aliases={
            **derived_compact_aliases,
            **explicit_compact_aliases
        },
        policy=_load_policy_config(policy_data, policy_source),
        providers=providers,
        provider_patterns=provider_patterns
    )
