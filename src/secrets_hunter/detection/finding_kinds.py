from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from secrets_hunter.immutability import frozen_mapping
from secrets_hunter.models.finding_kind import FindingKind


JWT_TOKEN_KIND = FindingKind("jwt_token", "JWT Token")
DB_CONNECTION_KIND = FindingKind(
    "db_connection_string",
    "DB Connection String"
)
PEM_KEY_KIND = FindingKind("pem_key", "PEM Key")
HIGH_ENTROPY_HEX_KIND = FindingKind(
    "high_entropy_hex",
    "High Entropy Hex String"
)
HIGH_ENTROPY_BASE64_KIND = FindingKind(
    "high_entropy_base64",
    "High Entropy Base64 String"
)

BUILTIN_FINDING_KINDS = (
    JWT_TOKEN_KIND,
    DB_CONNECTION_KIND,
    PEM_KEY_KIND,
    HIGH_ENTROPY_HEX_KIND,
    HIGH_ENTROPY_BASE64_KIND
)


@dataclass(frozen=True)
class FindingKindRegistry:
    kinds_by_id: Mapping[str, FindingKind]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "kinds_by_id",
            frozen_mapping(self.kinds_by_id)
        )

    def require(self, kind_id: str, source: str = "") -> FindingKind:
        kind = self.kinds_by_id.get(kind_id)

        if kind is not None:
            return kind

        where = f" in {source}" if source else ""
        expected = ", ".join(sorted(self.kinds_by_id))
        raise ValueError(
            f"Unknown finding kind ID {kind_id!r}{where}; "
            f"expected one of: {expected}"
        )


def build_finding_kind_registry(
    additional_kinds: Iterable[FindingKind] = ()
) -> FindingKindRegistry:
    kinds_by_id: dict[str, FindingKind] = {}
    ids_by_display_name: dict[str, str] = {}

    for kind in (*BUILTIN_FINDING_KINDS, *tuple(additional_kinds)):
        if not kind.id:
            raise ValueError("Finding kind ID must not be empty")

        if not kind.display_name:
            raise ValueError("Finding kind display name must not be empty")

        if kind.id in kinds_by_id:
            raise ValueError(f"Duplicate finding kind ID: {kind.id}")

        if kind.display_name in ids_by_display_name:
            raise ValueError(
                "Duplicate finding kind display name: "
                f"{kind.display_name}"
            )

        kinds_by_id[kind.id] = kind
        ids_by_display_name[kind.display_name] = kind.id

    return FindingKindRegistry(kinds_by_id)
