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
from secrets_hunter.detection.semantics.catalog import SemanticCatalog
from secrets_hunter.detection.value_patterns import JWT_TOKEN_RE
from secrets_hunter.models import FindingKind


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
            compiled=compile_regex(
                provider_pattern.regex,
                source=f"provider_patterns[{provider_pattern.id}]"
            ),
            provider_pattern_id=provider_pattern.id
        ))

    return build_pattern_detection_plan(patterns)
