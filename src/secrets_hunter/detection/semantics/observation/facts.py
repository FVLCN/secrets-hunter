from collections.abc import Mapping
from enum import StrEnum

from secrets_hunter.detection.semantics.evidence_sources import EvidenceSource
from secrets_hunter.models.fact import Fact, FactDetail


class FactId(StrEnum):
    ACTION_REFERENCE_LITERAL = "action_reference_literal"
    ASSERTED_HASH_VALUE = "asserted_hash_value"
    ENGLISH_WORDS_IN_VALUE = "english_words_in_value"
    HASH_CALL_ARGUMENT = "hash_call_argument"
    HASH_SHAPED_VALUE = "hash_shaped_value"
    HIGH_ENTROPY = "high_entropy"
    KNOWN_PATTERN_MATCH = "known_pattern_match"
    NO_ASSIGNMENT_CONTEXT = "no_assignment_context"
    PUBLIC_CRYPTO_ARTIFACT = "public_crypto_artifact"
    SAML_AUTHN_REQUEST_VALUE = "saml_authn_request_value"
    SHORT_ASSIGNMENT_NAME = "short_assignment_name"
    TERMINAL_IDENTIFIER_SUFFIX = "terminal_identifier_suffix"
    UNKNOWN_IDENTIFIER_CONTEXT = "unknown_identifier_context"


USAGE_FACT_IDS = frozenset({
    FactId.ACTION_REFERENCE_LITERAL,
    FactId.ASSERTED_HASH_VALUE,
    FactId.HASH_CALL_ARGUMENT,
    FactId.SAML_AUTHN_REQUEST_VALUE,
})


_FACT_PRESENTATIONS = {
    FactId.ACTION_REFERENCE_LITERAL: (
        "Action reference literal",
        None,
    ),
    FactId.ASSERTED_HASH_VALUE: (
        "Asserted hash value",
        None,
    ),
    FactId.ENGLISH_WORDS_IN_VALUE: (
        "English words in value",
        EvidenceSource.VALUE_ENGLISH_WORDS,
    ),
    FactId.HASH_CALL_ARGUMENT: (
        "Value passed to a hash function",
        None,
    ),
    FactId.HASH_SHAPED_VALUE: (
        "Hash-shaped value",
        EvidenceSource.VALUE_SHAPE,
    ),
    FactId.HIGH_ENTROPY: (
        "High entropy in value",
        None,
    ),
    FactId.KNOWN_PATTERN_MATCH: (
        "Known pattern match",
        EvidenceSource.FINDING_KIND,
    ),
    FactId.NO_ASSIGNMENT_CONTEXT: (
        "No assignment context",
        EvidenceSource.VAR_NAME,
    ),
    FactId.PUBLIC_CRYPTO_ARTIFACT: (
        "Public cryptographic artifact in value",
        EvidenceSource.VALUE_SHAPE,
    ),
    FactId.SAML_AUTHN_REQUEST_VALUE: (
        "SAML authentication request in value",
        None,
    ),
    FactId.SHORT_ASSIGNMENT_NAME: (
        "Short assignment name",
        EvidenceSource.VAR_NAME,
    ),
    FactId.TERMINAL_IDENTIFIER_SUFFIX: (
        "Terminal identifier suffix in name",
        EvidenceSource.NAME_ROLE,
    ),
    FactId.UNKNOWN_IDENTIFIER_CONTEXT: (
        "Unrecognized tokens in name",
        EvidenceSource.VAR_NAME,
    ),
}


def make_fact(
    name: FactId,
    evidence: str,
    *,
    details: Mapping[str, FactDetail] | None = None,
    sensitive: bool = False,
) -> Fact:
    display_name, source = _FACT_PRESENTATIONS[name]
    return Fact(
        name=name.value,
        display_name=display_name,
        evidence=evidence,
        source=source.value if source is not None else None,
        details=details or {},
        sensitive=sensitive,
    )
