import re

from dataclasses import dataclass
from enum import StrEnum


class RejectionKind(StrEnum):
    GENERIC = "generic"
    PLACEHOLDER = "placeholder"
    HASH = "hash"
    STRUCTURAL_PEM = "structural_pem"
    PUBLIC_CRYPTO = "public_crypto"


@dataclass(frozen=True)
class RejectionReason:
    kind: RejectionKind
    name: str
    category: str


@dataclass(frozen=True)
class RejectionPattern:
    pattern: re.Pattern[str]
    reason: RejectionReason
