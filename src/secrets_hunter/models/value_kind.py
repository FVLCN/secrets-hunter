from enum import StrEnum


class ValueKind(StrEnum):
    EMPTY = "empty"
    JWT = "jwt"
    UUID = "uuid"
    CREDENTIAL_URI = "credential_uri"
    HEX = "hex"
    BASE64 = "base64"
    BASE64URL = "base64url"
    BASE64_LIKE = "base64_like"
    GENERIC = "generic"
