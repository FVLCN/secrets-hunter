import re

from dataclasses import dataclass
from enum import StrEnum

from secrets_hunter.detection.value_patterns import HEX_VALUE_RE
from secrets_hunter.models.rejection import RejectionKind, RejectionReason


class HashAlgorithm(StrEnum):
    MD5 = "md5"
    SHA1 = "sha1"
    SHA224 = "sha224"
    SHA256 = "sha256"
    SHA384 = "sha384"
    SHA512 = "sha512"


@dataclass(frozen=True)
class HashSpec:
    display_name: str
    hex_length: int
    supports_sri: bool = False


HASH_SPECS: dict[HashAlgorithm, HashSpec] = {
    HashAlgorithm.MD5: HashSpec(
        display_name="MD5",
        hex_length=32
    ),
    HashAlgorithm.SHA1: HashSpec(
        display_name="SHA1",
        hex_length=40
    ),
    HashAlgorithm.SHA224: HashSpec(
        display_name="SHA224",
        hex_length=56
    ),
    HashAlgorithm.SHA256: HashSpec(
        display_name="SHA256",
        hex_length=64,
        supports_sri=True
    ),
    HashAlgorithm.SHA384: HashSpec(
        display_name="SHA384",
        hex_length=96,
        supports_sri=True
    ),
    HashAlgorithm.SHA512: HashSpec(
        display_name="SHA512",
        hex_length=128,
        supports_sri=True
    )
}

_HASH_ALGORITHM_BY_HEX_LENGTH = {
    spec.hex_length: algorithm
    for algorithm, spec in HASH_SPECS.items()
}
_HASH_ALGORITHM_PATTERN = "|".join(
    re.escape(algorithm.value)
    for algorithm in HashAlgorithm
)
_SRI_ALGORITHM_PATTERN = "|".join(
    re.escape(algorithm.value)
    for algorithm, spec in HASH_SPECS.items()
    if spec.supports_sri
)
_HASH_PREFIX_RE = re.compile(
    rf"^(?:{_HASH_ALGORITHM_PATTERN})[-:]",
    re.IGNORECASE
)
_SRI_HASH_VALUE_RE = re.compile(
    rf"(?P<algorithm>{_SRI_ALGORITHM_PATTERN})-[A-Za-z0-9+/]+={{0,2}}",
    re.IGNORECASE
)


@dataclass(frozen=True)
class HashValueClassification:
    algorithm: HashAlgorithm

    @property
    def shape_tokens(self) -> tuple[str, ...]:
        return ("hash",)

    @property
    def rejection_reason(self) -> RejectionReason:
        return RejectionReason(
            kind=RejectionKind.HASH,
            name=HASH_SPECS[self.algorithm].display_name,
            category="hash"
        )


def classify_hash_value(value: str) -> HashValueClassification | None:
    normalized = (value or "").strip()
    sri_match = _SRI_HASH_VALUE_RE.fullmatch(normalized)

    if sri_match:
        return HashValueClassification(
            algorithm=HashAlgorithm(sri_match.group("algorithm").lower())
        )

    if not HEX_VALUE_RE.fullmatch(normalized):
        return None

    algorithm = _HASH_ALGORITHM_BY_HEX_LENGTH.get(len(normalized))

    if algorithm is None:
        return None

    return HashValueClassification(
        algorithm=algorithm
    )


def strip_hash_prefix(value: str) -> str:
    return _HASH_PREFIX_RE.sub("", value or "", count=1)
