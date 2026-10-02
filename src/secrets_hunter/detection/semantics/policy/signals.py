from collections.abc import Mapping

from secrets_hunter.detection.semantics.catalog import ConceptId
from secrets_hunter.detection.semantics.evidence_sources import (
    EvidenceSource,
    evidence_source_spec
)

from .models import ConceptKeywordEvidence


_CREDENTIAL_CONCEPTS = frozenset({
    ConceptId.CONNECTION_CREDENTIAL,
    ConceptId.CREDENTIAL_GENERIC,
    ConceptId.KEY_CREDENTIAL,
    ConceptId.PASSWORD_CREDENTIAL,
    ConceptId.SECRET_CREDENTIAL,
    ConceptId.TOKEN_CREDENTIAL,
    ConceptId.WEBHOOK_CREDENTIAL
})


def _is_direct_secret_evidence(evidence: ConceptKeywordEvidence) -> bool:
    return evidence_source_spec(evidence.source).direct_secret


def has_strong_direct_credential_evidence(
    evidence_by_concept: Mapping[
        ConceptId,
        tuple[ConceptKeywordEvidence, ...]
    ]
) -> bool:
    for concept_id in _CREDENTIAL_CONCEPTS:
        for evidence in evidence_by_concept.get(concept_id, ()):
            if not _is_direct_secret_evidence(evidence):
                continue

            if concept_id is ConceptId.KEY_CREDENTIAL and evidence.term == "key":
                continue

            return True

    return False


def has_direct_fixture_evidence(
    evidence_by_concept: Mapping[
        ConceptId,
        tuple[ConceptKeywordEvidence, ...]
    ]
) -> bool:
    return any(
        evidence_source_spec(evidence.source).name_or_path
        for evidence in evidence_by_concept.get(ConceptId.TEST_FIXTURE, ())
    )


def has_direct_hash_artifact_evidence(
    evidence_by_concept: Mapping[
        ConceptId,
        tuple[ConceptKeywordEvidence, ...]
    ]
) -> bool:
    return bool(evidence_by_concept.get(ConceptId.HASH_ARTIFACT))


def has_direct_identifier_evidence(
    evidence_by_concept: Mapping[
        ConceptId,
        tuple[ConceptKeywordEvidence, ...]
    ]
) -> bool:
    return bool(evidence_by_concept.get(ConceptId.IDENTIFIER_CONTEXT))


def has_direct_ordinary_identifier_evidence(
    evidence_by_concept: Mapping[
        ConceptId,
        tuple[ConceptKeywordEvidence, ...]
    ]
) -> bool:
    return bool(
        evidence_by_concept.get(ConceptId.ORDINARY_IDENTIFIER_WORDS)
    )


def has_direct_reference_artifact_evidence(
    evidence_by_concept: Mapping[
        ConceptId,
        tuple[ConceptKeywordEvidence, ...]
    ]
) -> bool:
    return bool(
        evidence_by_concept.get(ConceptId.VERSION_OR_REFERENCE_ARTIFACT)
    )


def has_rejection_pattern_evidence(evidence: tuple[ConceptKeywordEvidence, ...]) -> bool:
    return any(keyword.source is EvidenceSource.REJECTION_PATTERN for keyword in evidence)


def has_value_shape_evidence(evidence: tuple[ConceptKeywordEvidence, ...]) -> bool:
    return any(keyword.source is EvidenceSource.VALUE_SHAPE for keyword in evidence)
