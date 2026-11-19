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


@dataclass(frozen=True)
class RejectionReason:
    kind: RejectionKind
    name: str
    category: str
    detail: str | None = None


@dataclass(frozen=True)
class RejectionPattern:
    pattern: re.Pattern[str]
    reason: RejectionReason
