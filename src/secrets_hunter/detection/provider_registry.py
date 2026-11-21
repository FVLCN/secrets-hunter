import re

from secrets_hunter.detection.detectors.models import DetectionPattern
from secrets_hunter.detection.finding_kinds import (
    JWT_TOKEN_KIND,
    FindingKindRegistry,
    build_finding_kind_registry
)
from secrets_hunter.detection.pattern_plan import (
    PatternDetectionPlan,
    build_pattern_detection_plan
)
from secrets_hunter.detection.regex import compile_regex
from secrets_hunter.detection.semantics.catalog import (
    ProviderPatternClassification,
    ProviderPattern,
    SemanticCatalog,
)
from secrets_hunter.detection.patterns.values import JWT_TOKEN_RE
from secrets_hunter.models import (
    FindingKind,
    RejectionKind,
    RejectionPattern,
    RejectionReason,
)


def finding_kind_registry_for_catalog(
    catalog: SemanticCatalog
) -> FindingKindRegistry:
    return build_finding_kind_registry(
        FindingKind(
            id=provider_pattern.id,
            display_name=provider_pattern.name
        )
        for provider_pattern in catalog.provider_patterns
    )


def compile_provider_pattern(
    provider_pattern: ProviderPattern,
) -> re.Pattern[str]:
    if provider_pattern.regex is not None:
        regex = provider_pattern.regex
    else:
        value = provider_pattern.value
        if value is None:
            raise ValueError(
                f"Provider pattern {provider_pattern.id!r} has no match value"
            )
        regex = _exact_value_regex(value)

    return compile_regex(
        regex,
        source=f"provider_patterns[{provider_pattern.id}]"
    )


def _exact_value_regex(value: str) -> str:
    """Match a literal value only when it is a complete provider token."""
    escaped_value = re.escape(value)
    token_characters = "A-Za-z0-9_-"
    before_token = rf"(?<![{token_characters}])"
    after_token = rf"(?![{token_characters}])"
    return f"{before_token}{escaped_value}{after_token}"


def provider_pattern_rejection_patterns(
    catalog: SemanticCatalog,
) -> tuple[RejectionPattern, ...]:
    rejection_patterns: list[RejectionPattern] = []

    for provider_pattern in catalog.provider_patterns:
        if (
            provider_pattern.classification
            is ProviderPatternClassification.PUBLIC_CREDENTIAL
        ):
            kind = RejectionKind.KNOWN_PUBLIC_SECRET
            category = "known public value"
        elif (
            provider_pattern.classification
            is ProviderPatternClassification.NON_SECRET_IDENTIFIER
        ):
            kind = RejectionKind.PROVIDER_IDENTIFIER
            category = "provider identifier"
        else:
            continue

        rejection_patterns.append(RejectionPattern(
            pattern=compile_provider_pattern(provider_pattern),
            reason=RejectionReason(
                kind=kind,
                name=provider_pattern.id,
                category=category,
                detail=provider_pattern.reason or provider_pattern.name,
            ),
        ))

    return tuple(rejection_patterns)


def provider_detection_plan(
    catalog: SemanticCatalog,
    finding_kinds: FindingKindRegistry
) -> PatternDetectionPlan:
    patterns = [
        DetectionPattern(
            kind=finding_kinds.require(JWT_TOKEN_KIND.id),
            compiled=JWT_TOKEN_RE
        )
    ]

    for provider_pattern in catalog.provider_patterns:
        patterns.append(DetectionPattern(
            kind=finding_kinds.require(
                provider_pattern.id,
                source="provider patterns"
            ),
            compiled=compile_provider_pattern(provider_pattern),
            provider_pattern_id=provider_pattern.id
        ))

    return build_pattern_detection_plan(patterns)
