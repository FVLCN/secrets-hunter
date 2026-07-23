from enum import StrEnum


class FactId(StrEnum):
    ENGLISH_WORDS_IN_VALUE = "english_words_in_value"
    HIGH_ENTROPY = "high_entropy"
    KNOWN_PATTERN_MATCH = "known_pattern_match"
    NO_ASSIGNMENT_CONTEXT = "no_assignment_context"
    PUBLIC_CRYPTO_ARTIFACT = "public_crypto_artifact"
    UNKNOWN_IDENTIFIER_CONTEXT = "unknown_identifier_context"
