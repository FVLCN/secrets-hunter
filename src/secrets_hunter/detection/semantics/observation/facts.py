from enum import StrEnum


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
