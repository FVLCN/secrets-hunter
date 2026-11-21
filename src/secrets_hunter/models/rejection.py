import re

from dataclasses import dataclass
from enum import StrEnum


class RejectionKind(StrEnum):
    GENERIC = "generic"
    PLACEHOLDER = "placeholder"
    HASH = "hash"
    STRUCTURAL_PEM = "structural_pem"
    STRUCTURAL_VALUE = "structural_value"
    PUBLIC_CRYPTO = "public_crypto"
    KNOWN_PUBLIC_SECRET = "known_public_secret"
    PROVIDER_IDENTIFIER = "provider_identifier"


class RejectionId(StrEnum):
    GIT_SIGNING_KEY_REFERENCE = "git_signing_key_reference"
    DARKTABLE_PARAMETER = "darktable_parameter"
    CODE_IDENTIFIER_REFERENCE = "code_identifier_reference"
    GIT_COMMIT_REFERENCE = "git_commit_reference"
    PUBLIC_SSH_KEY = "public_ssh_key"
    PUBLIC_PAYMENT_ADDRESS = "public_payment_address"
    ABBREVIATED_JWT_EXAMPLE = "abbreviated_jwt_example"


class RejectionEvidenceId(StrEnum):
    GIT_CONFIG_PATH = "git_config_path"
    GPG_KEY_ID_FORMAT = "gpg_key_id_format"
    DARKTABLE_FILE_EXTENSION = "darktable_file_extension"
    DARKTABLE_PARAMETER_NAME = "darktable_parameter_name"
    DARKTABLE_HEX_PARAMETER = "darktable_hex_parameter"
    DARKTABLE_COMPRESSED_PARAMETER = "darktable_compressed_parameter"
    CODE_FILE_EXTENSION = "code_file_extension"
    JS_TS_IDENTIFIER_USE = "js_ts_identifier_use"
    GIT_COMMIT_URL_CONTEXT = "git_commit_url_context"
    ACTION_COMMIT_PIN_CONTEXT = "action_commit_pin_context"
    ACTION_COMMIT_COMMENT_CONTEXT = "action_commit_comment_context"
    SSH_PUBLIC_KEY_FORMAT = "ssh_public_key_format"
    BASE58CHECK_PAYMENT_ADDRESS = "base58check_payment_address"
    ABBREVIATED_JWT_CONTEXT = "abbreviated_jwt_context"


class RejectionEvidenceKind(StrEnum):
    PATH = "path"
    SOURCE_CONTEXT = "source_context"
    VALUE_SHAPE = "value_shape"


@dataclass(frozen=True)
class RejectionEvidence:
    id: RejectionEvidenceId
    match: str | None = None


@dataclass(frozen=True)
class RejectionReason:
    kind: RejectionKind
    name: str
    category: str
    detail: str | None = None
    reason_id: RejectionId | None = None
    evidence: tuple[RejectionEvidence, ...] = ()


@dataclass(frozen=True)
class RejectionPattern:
    pattern: re.Pattern[str]
    reason: RejectionReason
