from dataclasses import dataclass

from secrets_hunter.detection.semantics.evidence_sources import (
    EVIDENCE_SOURCE_SPECS,
    EvidenceSource,
)
from secrets_hunter.detection.pem import PemAnalysis
from secrets_hunter.detection.value_analysis import ValueAnalysis
from secrets_hunter.models import (
    DetectionMethod,
    FindingKind,
    RejectionReason,
    ValueKind
)

from .facts import FactId


@dataclass(frozen=True)
class SemanticInput:
    associated_name: str
    detection_method: DetectionMethod
    finding_kind: FindingKind
    file_path: str
    value_analysis: ValueAnalysis
    lexical_subject: str | None = None
    pem_analysis: PemAnalysis | None = None
    value_rejection: RejectionReason | None = None
    provider_pattern_id: str | None = None


@dataclass(frozen=True)
class SemanticObservation:
    finding_kind: FindingKind
    value_kind: ValueKind
    name_tokens: tuple[str, ...]
    name_role_tokens: tuple[str, ...]
    neutral_identifier_tokens: tuple[str, ...]
    unknown_identifier_tokens: tuple[str, ...]
    file_extension: str
    file_extension_tokens: tuple[str, ...]
    path_tokens: tuple[str, ...]
    finding_kind_tokens: tuple[str, ...]
    rejection_pattern_tokens: tuple[str, ...]
    value_shape_tokens: tuple[str, ...]
    value_length_bucket: str
    value_entropy_bucket: str
    english_words_in_value_tokens: tuple[str, ...]
    value_rejection: RejectionReason | None = None
    provider_pattern_id: str | None = None
    facts: frozenset[FactId] = frozenset()

    def has_fact(self, fact: FactId) -> bool:
        return fact in self.facts

    def evidence_tokens_by_source(self) -> dict[EvidenceSource, tuple[str, ...]]:
        return {
            source: getattr(self, spec.observation_field)
            for source, spec in EVIDENCE_SOURCE_SPECS.items()
            if spec.observation_field is not None
        }
