from secrets_hunter.detection.semantics.evidence_sources import EvidenceSource

from .models import ConceptKeywordEvidence


def has_rejection_pattern_evidence(evidence: tuple[ConceptKeywordEvidence, ...]) -> bool:
    return any(keyword.source is EvidenceSource.REJECTION_PATTERN for keyword in evidence)


def has_value_shape_evidence(evidence: tuple[ConceptKeywordEvidence, ...]) -> bool:
    return any(keyword.source is EvidenceSource.VALUE_SHAPE for keyword in evidence)
