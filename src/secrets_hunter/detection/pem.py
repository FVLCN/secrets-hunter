import re

from dataclasses import dataclass
from enum import StrEnum


class PemType(StrEnum):
    PRIVATE_KEY = "PRIVATE KEY"
    PUBLIC_KEY = "PUBLIC KEY"
    CERTIFICATE = "CERTIFICATE"
    RSA_PRIVATE_KEY = "RSA PRIVATE KEY"
    RSA_PUBLIC_KEY = "RSA PUBLIC KEY"
    EC_PRIVATE_KEY = "EC PRIVATE KEY"
    DSA_PRIVATE_KEY = "DSA PRIVATE KEY"
    OPENSSH_PRIVATE_KEY = "OPENSSH PRIVATE KEY"
    ENCRYPTED_PRIVATE_KEY = "ENCRYPTED PRIVATE KEY"
    CERTIFICATE_REQUEST = "CERTIFICATE REQUEST"
    CRL = "CRL"
    PGP_PUBLIC_KEY_BLOCK = "PGP PUBLIC KEY BLOCK"
    PGP_PRIVATE_KEY_BLOCK = "PGP PRIVATE KEY BLOCK"

    @property
    def footer_marker(self) -> str:
        return f"-----END {self.value}-----"


class PemDisposition(StrEnum):
    SECRET_MATERIAL = "secret_material"
    PUBLIC_ARTIFACT = "public_artifact"


@dataclass(frozen=True)
class PemTypeSpec:
    disposition: PemDisposition
    shape_tokens: tuple[str, ...]
    display_category: str


PEM_TYPE_SPECS: dict[PemType, PemTypeSpec] = {
    PemType.PRIVATE_KEY: PemTypeSpec(
        disposition=PemDisposition.SECRET_MATERIAL,
        shape_tokens=(),
        display_category="Private key"
    ),
    PemType.PUBLIC_KEY: PemTypeSpec(
        disposition=PemDisposition.PUBLIC_ARTIFACT,
        shape_tokens=("public", "key"),
        display_category="Key"
    ),
    PemType.CERTIFICATE: PemTypeSpec(
        disposition=PemDisposition.PUBLIC_ARTIFACT,
        shape_tokens=("certificate", "public"),
        display_category="Certificate"
    ),
    PemType.RSA_PRIVATE_KEY: PemTypeSpec(
        disposition=PemDisposition.SECRET_MATERIAL,
        shape_tokens=(),
        display_category="RSA private key"
    ),
    PemType.RSA_PUBLIC_KEY: PemTypeSpec(
        disposition=PemDisposition.PUBLIC_ARTIFACT,
        shape_tokens=("public", "key"),
        display_category="RSA public key"
    ),
    PemType.EC_PRIVATE_KEY: PemTypeSpec(
        disposition=PemDisposition.SECRET_MATERIAL,
        shape_tokens=(),
        display_category="EC private key"
    ),
    PemType.DSA_PRIVATE_KEY: PemTypeSpec(
        disposition=PemDisposition.SECRET_MATERIAL,
        shape_tokens=(),
        display_category="DSA private key"
    ),
    PemType.OPENSSH_PRIVATE_KEY: PemTypeSpec(
        disposition=PemDisposition.SECRET_MATERIAL,
        shape_tokens=(),
        display_category="OpenSSH private key"
    ),
    PemType.ENCRYPTED_PRIVATE_KEY: PemTypeSpec(
        disposition=PemDisposition.SECRET_MATERIAL,
        shape_tokens=(),
        display_category="Encrypted private key"
    ),
    PemType.CERTIFICATE_REQUEST: PemTypeSpec(
        disposition=PemDisposition.PUBLIC_ARTIFACT,
        shape_tokens=("certificate", "request", "public"),
        display_category="Certificate request"
    ),
    PemType.CRL: PemTypeSpec(
        disposition=PemDisposition.PUBLIC_ARTIFACT,
        shape_tokens=("certificate", "revocation", "public"),
        display_category="Certificate revocation list"
    ),
    PemType.PGP_PUBLIC_KEY_BLOCK: PemTypeSpec(
        disposition=PemDisposition.PUBLIC_ARTIFACT,
        shape_tokens=("public", "key", "pubkey"),
        display_category="PGP public key"
    ),
    PemType.PGP_PRIVATE_KEY_BLOCK: PemTypeSpec(
        disposition=PemDisposition.SECRET_MATERIAL,
        shape_tokens=(),
        display_category="PGP private key"
    )
}

PEM_GROUP_PATTERN = "|".join(re.escape(pem_type.value) for pem_type in PemType)
PEM_BEGIN_RE = re.compile(rf"-----BEGIN ({PEM_GROUP_PATTERN})-----")
PEM_END_RE = re.compile(rf"-----END ({PEM_GROUP_PATTERN})-----")
PEM_BASE64_BODY_RE = re.compile(r"[A-Za-z0-9+/]*={0,2}")
MIN_PEM_BODY_BYTES = 16


@dataclass(frozen=True)
class PemAnalysis:
    pem_type: PemType
    disposition: PemDisposition
    shape_tokens: tuple[str, ...]
    display_category: str


def analyze_pem_header(header: str) -> PemAnalysis | None:
    match = PEM_BEGIN_RE.fullmatch(header.strip())

    if not match:
        return None

    pem_type = PemType(match.group(1))
    spec = PEM_TYPE_SPECS[pem_type]

    return PemAnalysis(
        pem_type=pem_type,
        disposition=spec.disposition,
        shape_tokens=spec.shape_tokens,
        display_category=spec.display_category
    )
