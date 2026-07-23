from enum import StrEnum

from secrets_hunter.detection.semantics.parsing import normalize_token, require_string


SEMANTIC_ONTOLOGY_VERSION = 1


class ConceptId(StrEnum):
    AUTH_SYSTEM_TARGET = "auth_system_target"
    CLOUD_PROVIDER_TARGET = "cloud_provider_target"
    CONNECTION_CREDENTIAL = "connection_credential"
    CREDENTIAL_GENERIC = "credential_generic"
    GENERIC_ASSIGNMENT_NAME = "generic_assignment_name"
    HASH_ARTIFACT = "hash_artifact"
    IDENTIFIER_CONTEXT = "identifier_context"
    INFRASTRUCTURE_TARGET = "infrastructure_target"
    KEY_CREDENTIAL = "key_credential"
    ORDINARY_IDENTIFIER_WORDS = "ordinary_identifier_words"
    PASSWORD_CREDENTIAL = "password_credential"
    PLACEHOLDER_VALUE = "placeholder_value"
    PRODUCT_SERVICE_TARGET = "product_service_target"
    PUBLIC_CRYPTO_ARTIFACT = "public_crypto_artifact"
    SECRET_CREDENTIAL = "secret_credential"
    TEST_FIXTURE = "test_fixture"
    TOKEN_CREDENTIAL = "token_credential"
    VERSION_OR_REFERENCE_ARTIFACT = "version_or_reference_artifact"
    WEBHOOK_CREDENTIAL = "webhook_credential"


class ConceptCategory(StrEnum):
    CREDENTIAL = "credential"
    HARD_REJECT = "hard_reject"
    IDENTIFIER_SIGNAL = "identifier_signal"
    NEUTRAL = "neutral"
    NON_SECRET_ARTIFACT = "non_secret_artifact"
    REJECTION_PATTERN = "rejection_pattern"
    SECRET_TARGET = "secret_target"
    WEAK_NEGATIVE = "weak_negative"


class ConceptPolicy(StrEnum):
    CONTEXT_REJECT_EVIDENCE = "context_reject_evidence"
    EVIDENCE = "evidence"
    HARD_REJECT = "hard_reject"
    NEUTRAL = "neutral"
    NEUTRAL_REJECT_EVIDENCE = "neutral_reject_evidence"
    REJECT_EVIDENCE = "reject_evidence"
    VALUE_REJECT = "value_reject"


def _require_taxonomy_value[_TaxonomyValue: StrEnum](
    value: object,
    key: str,
    source: str,
    value_type: type[_TaxonomyValue]
) -> _TaxonomyValue:
    normalized = normalize_token(require_string(value, key, source))

    try:
        return value_type(normalized)
    except ValueError as exc:
        expected = ", ".join(item.value for item in value_type)
        raise ValueError(
            f"Unknown {key} {normalized!r} in {source}; expected one of: {expected}"
        ) from exc


def require_concept_id(value: object, key: str, source: str) -> ConceptId:
    return _require_taxonomy_value(value, key, source, ConceptId)


def require_concept_category(value: object, source: str) -> ConceptCategory:
    return _require_taxonomy_value(value, "concept category", source, ConceptCategory)


def require_concept_policy(value: object, source: str) -> ConceptPolicy:
    return _require_taxonomy_value(value, "concept policy", source, ConceptPolicy)
