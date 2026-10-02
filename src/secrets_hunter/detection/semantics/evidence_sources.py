from dataclasses import dataclass
from enum import StrEnum


class EvidenceSource(StrEnum):
    VAR_NAME = "var_name"
    NAME_ROLE = "name_role"
    PATH = "path"
    FILE_EXTENSION = "file_extension"
    FINDING_KIND = "finding_kind"
    PROVIDER_PATTERN = "provider_pattern"
    VALUE_SHAPE = "value_shape"
    REJECTION_PATTERN = "rejection_pattern"
    VALUE_ENGLISH_WORDS = "value_english_words"


@dataclass(frozen=True)
class EvidenceSourceSpec:
    priority: int
    catalog_allowed: bool
    observation_field: str | None = None
    name_or_path: bool = False
    direct_secret: bool = False
    provider_matchable: bool = False


EVIDENCE_SOURCE_SPECS: dict[EvidenceSource, EvidenceSourceSpec] = {
    EvidenceSource.VAR_NAME: EvidenceSourceSpec(
        priority=0,
        catalog_allowed=True,
        observation_field="name_tokens",
        name_or_path=True,
        direct_secret=True,
        provider_matchable=True
    ),
    EvidenceSource.NAME_ROLE: EvidenceSourceSpec(
        priority=1,
        catalog_allowed=True,
        observation_field="name_role_tokens",
        name_or_path=True
    ),
    EvidenceSource.PATH: EvidenceSourceSpec(
        priority=2,
        catalog_allowed=True,
        observation_field="path_tokens",
        name_or_path=True,
        provider_matchable=True
    ),
    EvidenceSource.FILE_EXTENSION: EvidenceSourceSpec(
        priority=3,
        catalog_allowed=True,
        observation_field="file_extension_tokens",
        name_or_path=True
    ),
    EvidenceSource.FINDING_KIND: EvidenceSourceSpec(
        priority=4,
        catalog_allowed=True,
        observation_field="finding_kind_tokens",
        direct_secret=True
    ),
    EvidenceSource.PROVIDER_PATTERN: EvidenceSourceSpec(
        priority=5,
        catalog_allowed=False,
        direct_secret=True
    ),
    EvidenceSource.VALUE_SHAPE: EvidenceSourceSpec(
        priority=6,
        catalog_allowed=True,
        observation_field="value_shape_tokens"
    ),
    EvidenceSource.REJECTION_PATTERN: EvidenceSourceSpec(
        priority=7,
        catalog_allowed=True,
        observation_field="rejection_pattern_tokens",
        direct_secret=True
    ),
    EvidenceSource.VALUE_ENGLISH_WORDS: EvidenceSourceSpec(
        priority=8,
        catalog_allowed=True,
        observation_field="english_words_in_value_tokens",
        direct_secret=True
    )
}


def evidence_source_spec(source: EvidenceSource) -> EvidenceSourceSpec:
    return EVIDENCE_SOURCE_SPECS[source]


def evidence_source_priority(source: EvidenceSource) -> int:
    return evidence_source_spec(source).priority


def provider_matchable_evidence_sources() -> tuple[EvidenceSource, ...]:
    return tuple(
        source
        for source, spec in EVIDENCE_SOURCE_SPECS.items()
        if spec.provider_matchable
    )
