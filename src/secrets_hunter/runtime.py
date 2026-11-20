from dataclasses import dataclass
from pathlib import Path

from secrets_hunter.config import RuntimeConfig, load_runtime_config
from secrets_hunter.detection.default_value_classification import (
    build_default_value_classifier
)
from secrets_hunter.detection.finding_kinds import FindingKindRegistry
from secrets_hunter.detection.pattern_plan import PatternDetectionPlan
from secrets_hunter.detection.provider_registry import (
    finding_kind_registry_for_catalog,
    provider_detection_plan
)
from secrets_hunter.detection.semantics import SemanticRuntime
from secrets_hunter.detection.semantics.catalog import load_semantic_catalog
from secrets_hunter.detection.value_classification import ValueClassifier


@dataclass(frozen=True)
class ApplicationRuntime:
    config: RuntimeConfig
    semantics: SemanticRuntime
    finding_kinds: FindingKindRegistry
    pattern_plan: PatternDetectionPlan
    value_classifier: ValueClassifier


def load_application_runtime(
    user_configs: list[str | Path] | None = None
) -> ApplicationRuntime:
    semantic_catalog = load_semantic_catalog()
    finding_kinds = finding_kind_registry_for_catalog(semantic_catalog)

    return ApplicationRuntime(
        config=load_runtime_config(user_configs),
        semantics=SemanticRuntime.from_catalog(semantic_catalog),
        finding_kinds=finding_kinds,
        pattern_plan=provider_detection_plan(
            semantic_catalog,
            finding_kinds
        ),
        value_classifier=build_default_value_classifier()
    )
