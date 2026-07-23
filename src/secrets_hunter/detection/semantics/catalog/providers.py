from collections.abc import Mapping

from secrets_hunter.detection.semantics.parsing import (
    normalize_token,
    require_string,
    require_string_list,
    require_table
)

from .models import Provider, ProviderPattern
from .taxonomy import ConceptId, require_concept_id
from .validation import require_unique_ids


def _load_provider_kind_targets(
    data: Mapping[str, object],
    source: str
) -> dict[str, ConceptId]:
    raw_targets = data.get("provider_kind_targets") or {}

    target_table = require_table(
        raw_targets,
        "provider_kind_targets",
        source
    )

    provider_kind_targets: dict[str, ConceptId] = {}

    for raw_kind, raw_target in target_table.items():
        kind = normalize_token(raw_kind)
        target = require_concept_id(
            raw_target,
            f"provider_kind_targets.{raw_kind}",
            source
        )

        if not kind:
            raise ValueError(f"Provider kind must not be empty in {source}")

        provider_kind_targets[kind] = target

    if not provider_kind_targets:
        raise ValueError(f"'provider_kind_targets' must not be empty in {source}")

    return provider_kind_targets


def _load_providers(
    data: Mapping[str, object],
    source: str,
    provider_kind_targets: Mapping[str, ConceptId]
) -> tuple[Provider, ...]:
    raw_providers = data.get("providers") or []

    if not isinstance(raw_providers, list):
        raise ValueError(f"'providers' must be an array in {source}")

    providers: list[Provider] = []

    for raw_provider in raw_providers:
        provider_data = require_table(raw_provider, "providers entry", source)

        provider_id = normalize_token(require_string(provider_data.get("id"), "id", source))
        kind = normalize_token(require_string(provider_data.get("kind"), "kind", source))
        target_concept = provider_kind_targets.get(kind)
        terms = tuple(dict.fromkeys(
            normalize_token(term)
            for term in require_string_list(provider_data, "terms", source)
        ))

        if not terms:
            raise ValueError(f"Provider {provider_id!r} in {source} must define terms")

        if "target_concept" in provider_data:
            raise ValueError(
                f"Provider {provider_id!r} in {source} must not define target_concept; "
                "use provider_kind_targets instead"
            )

        if not target_concept:
            raise ValueError(
                f"Provider {provider_id!r} in {source} uses unmapped provider kind {kind!r}"
            )

        providers.append(
            Provider(
                id=provider_id,
                name=require_string(provider_data.get("name"), "name", source),
                kind=kind,
                target_concept=target_concept,
                terms=terms
            )
        )

    require_unique_ids(
        (provider.id for provider in providers),
        "provider",
        source
    )

    return tuple(providers)


def _load_provider_patterns(
    data: Mapping[str, object],
    source: str
) -> tuple[ProviderPattern, ...]:
    raw_patterns = data.get("provider_patterns") or []

    if not isinstance(raw_patterns, list):
        raise ValueError(f"'provider_patterns' must be an array in {source}")

    provider_patterns: list[ProviderPattern] = []

    for raw_pattern in raw_patterns:
        pattern_data = require_table(
            raw_pattern,
            "provider_patterns entry",
            source
        )

        provider_patterns.append(
            ProviderPattern(
                id=normalize_token(require_string(pattern_data.get("id"), "id", source)),
                provider_id=normalize_token(
                    require_string(pattern_data.get("provider"), "provider", source)
                ),
                name=require_string(pattern_data.get("name"), "name", source),
                regex=require_string(pattern_data.get("regex"), "regex", source)
            )
        )

    require_unique_ids(
        (pattern.id for pattern in provider_patterns),
        "provider pattern",
        source
    )

    return tuple(provider_patterns)
