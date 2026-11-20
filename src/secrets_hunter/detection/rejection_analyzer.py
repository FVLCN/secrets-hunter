import base64
import hashlib
import json
import re
import zlib

from collections.abc import Iterable
from binascii import Error as BinasciiError
from functools import lru_cache
from pathlib import PurePath

from secrets_hunter.detection.pem import (
    MIN_PEM_BODY_BYTES,
    PemDisposition,
    normalize_pem_body
)
from secrets_hunter.detection.patterns.darktable import (
    DARKTABLE_COMPRESSED_VALUE_RE,
    DARKTABLE_HEX_VALUE_RE,
    DARKTABLE_PARAMETER_RE,
)
from secrets_hunter.detection.patterns.git_references import (
    ACTION_COMMENT_COMMIT_PATTERN,
    ACTION_COMMIT_PIN_PATTERN,
    COMMIT_ID_RE,
    COMMIT_URL_REFERENCE_PATTERN,
    GPG_KEY_ID_RE,
)
from secrets_hunter.detection.patterns.javascript import (
    JS_AS_CONTEXT_RE,
    JS_DECLARATION_CONTEXT_RE,
    JS_IDENTIFIER_OCCURRENCE_PATTERN,
    JS_IDENTIFIER_RE,
    JS_IMPORT_CONTEXT_RE,
    JS_NON_CODE_RE,
    JS_REFERENCE_ARRAY_CONTEXT_RE,
    JS_TYPE_PREDICATE_CONTEXT_RE,
    JS_TYPE_UNION_CONTEXT_RE,
)
from secrets_hunter.detection.patterns.values import (
    ABBREVIATED_JWT_REFERENCE_PATTERN,
    BASE64_STANDARD_VALUE_RE,
    BASE64URL_UNPADDED_RE,
    DB_EXAMPLE_URI_RE,
    DB_PASSWORD_IN_URI_RE,
    DB_PLACEHOLDER_RE,
    POSTGRES_LOCAL_DEFAULT_URI_RE,
)
from secrets_hunter.detection.detectors.models import DetectionCandidate
from secrets_hunter.detection.fragmenter import DBConnectionFragment, PEMKeyFragment
from secrets_hunter.detection.hash_classification import HashValueClassification
from secrets_hunter.detection.source_languages import is_js_ts_source
from secrets_hunter.models import (
    DetectionMethod,
    RejectionKind,
    RejectionPattern,
    RejectionReason,
)


_MAX_DARKTABLE_PARAMETER_BYTES = 1024 * 1024
_MAX_ABBREVIATED_JWT_HEADER_CHARS = 4096
_MAX_CACHED_JS_SOURCE_CHARS = 1024
_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

MISSING_PEM_BODY = RejectionReason(
    kind=RejectionKind.STRUCTURAL_PEM,
    name="Missing",
    category="PEM body"
)
TOO_SHORT_PEM_BODY = RejectionReason(
    kind=RejectionKind.STRUCTURAL_PEM,
    name="Too short",
    category="PEM body"
)
INVALID_PEM_BODY = RejectionReason(
    kind=RejectionKind.STRUCTURAL_PEM,
    name="Invalid",
    category="PEM base64 body"
)
MISSING_PEM_FOOTER = RejectionReason(
    kind=RejectionKind.STRUCTURAL_PEM,
    name="Missing",
    category="PEM footer"
)
DB_CONN_PLACEHOLDER = RejectionPattern(
    pattern=DB_PLACEHOLDER_RE,
    reason=RejectionReason(
        kind=RejectionKind.PLACEHOLDER,
        name="db connection",
        category="placeholder"
    )
)


def _mask_js_non_code(source_text: str) -> str:
    return JS_NON_CODE_RE.sub(lambda match: " " * len(match.group()), source_text)


_cached_js_code = lru_cache(maxsize=256)(_mask_js_non_code)


class CandidateRejectionAnalyzer:
    def __init__(
        self,
        rejection_patterns: Iterable[RejectionPattern]
    ) -> None:
        patterns = tuple(rejection_patterns)
        self.known_public_patterns = tuple(
            pattern for pattern in patterns
            if pattern.reason.kind is RejectionKind.KNOWN_PUBLIC_SECRET
        )
        self.rejection_patterns = tuple(
            pattern for pattern in patterns
            if pattern.reason.kind is not RejectionKind.KNOWN_PUBLIC_SECRET
        )

    @staticmethod
    def is_abbreviated_jwt(value: str, source_text: str) -> bool:
        if (
            "..." not in source_text
            or len(value) > _MAX_ABBREVIATED_JWT_HEADER_CHARS
            or source_text.count(value) != 1
            or not BASE64URL_UNPADDED_RE.fullmatch(value)
        ):
            return False

        if not re.search(
            ABBREVIATED_JWT_REFERENCE_PATTERN.format(value=re.escape(value)),
            source_text,
        ):
            return False

        try:
            decoded = base64.b64decode(
                value + "=" * (-len(value) % 4),
                altchars=b"-_",
                validate=True,
            )
            header = json.loads(decoded.decode("utf-8"))
        except (ValueError, RecursionError):
            return False

        return (
            isinstance(header, dict)
            and set(header) == {"alg", "typ"}
            and isinstance(header["alg"], str)
            and bool(header["alg"].strip())
            and header["typ"] == "JWT"
        )

    @staticmethod
    def is_code_reference(value: str, source_text: str, path: PurePath) -> bool:
        if not is_js_ts_source(path) or not JS_IDENTIFIER_RE.fullmatch(value):
            return False

        code = (
            _cached_js_code(source_text)
            if len(source_text) <= _MAX_CACHED_JS_SOURCE_CHARS
            else _mask_js_non_code(source_text)
        )
        occurrences = list(re.finditer(
            JS_IDENTIFIER_OCCURRENCE_PATTERN.format(value=re.escape(value)), source_text
        ))
        if not occurrences or any(
            code[match.start():match.end()] != value for match in occurrences
        ):
            return False

        for match in occurrences:
            before = code[:match.start()].rstrip()
            after = code[match.end():].lstrip()
            if (
                before.endswith((".", ":", "="))
                or after.startswith((":", "("))
                or JS_IMPORT_CONTEXT_RE.search(before)
                or JS_DECLARATION_CONTEXT_RE.search(before)
                or JS_TYPE_PREDICATE_CONTEXT_RE.search(before)
                or JS_AS_CONTEXT_RE.search(before)
                or JS_TYPE_UNION_CONTEXT_RE.search(before)
                or JS_REFERENCE_ARRAY_CONTEXT_RE.search(before)
            ):
                return True

        return False

    @staticmethod
    def is_public_payment_address(value: str) -> bool:
        if not 26 <= len(value) <= 35:
            return False

        number = 0
        for char in value:
            digit = _BASE58_ALPHABET.find(char)
            if digit < 0:
                return False
            number = number * 58 + digit

        decoded = (
            b"\x00" * (len(value) - len(value.lstrip("1")))
            + number.to_bytes((number.bit_length() + 7) // 8, "big")
        )
        if len(decoded) != 25 or decoded[0] not in {0, 76}:
            return False

        checksum = hashlib.sha256(hashlib.sha256(decoded[:-4]).digest()).digest()[:4]
        return decoded[-4:] == checksum

    @staticmethod
    def is_commit_reference(value: str, source_text: str) -> bool:
        if not COMMIT_ID_RE.fullmatch(value):
            return False

        escaped = re.escape(value)
        return any(re.search(pattern, source_text) for pattern in (
            COMMIT_URL_REFERENCE_PATTERN.format(value=escaped),
            ACTION_COMMIT_PIN_PATTERN.format(value=escaped),
            ACTION_COMMENT_COMMIT_PATTERN.format(value=escaped),
        ))

    @classmethod
    def is_darktable_processing_value(
        cls, value: str, source_text: str, path: PurePath
    ) -> bool:
        if path.suffix.lower() != ".xmp" or not any(
            match.group(2) == value
            for match in DARKTABLE_PARAMETER_RE.finditer(source_text)
        ):
            return False

        if DARKTABLE_HEX_VALUE_RE.fullmatch(value):
            return len(value) // 2 <= _MAX_DARKTABLE_PARAMETER_BYTES

        # Darktable stores compressed parameters as gz + two-digit factor + Base64.
        if not DARKTABLE_COMPRESSED_VALUE_RE.fullmatch(value):
            return False
        compressed = cls.decode_base64_body(value[4:])
        if compressed is None:
            return False

        decoder = zlib.decompressobj()
        try:
            decoded = decoder.decompress(compressed, _MAX_DARKTABLE_PARAMETER_BYTES + 1)
        except zlib.error:
            return False
        return (
            0 < len(decoded) <= _MAX_DARKTABLE_PARAMETER_BYTES
            and decoder.eof
            and not decoder.unused_data
            and not decoder.unconsumed_tail
        )

    @classmethod
    def is_ssh_public_key(cls, value: str) -> bool:
        fields = value.split()
        body = fields[1] if len(fields) > 1 and fields[0].startswith(("ssh-", "ecdsa-")) else value
        decoded = cls.decode_base64_body(body)
        if decoded is None:
            return False

        offset = 0

        def read_string() -> bytes | None:
            nonlocal offset
            if offset + 4 > len(decoded):
                return None
            length = int.from_bytes(decoded[offset:offset + 4], "big")
            offset += 4
            end = offset + length
            if end > len(decoded):
                return None
            field = decoded[offset:end]
            offset = end
            return field

        algorithm = read_string()
        if algorithm is None:
            return False
        count = {
            b"ssh-rsa": 2,
            b"ssh-dss": 4,
            b"ssh-ed25519": 1,
            b"ecdsa-sha2-nistp256": 2,
            b"ecdsa-sha2-nistp384": 2,
            b"ecdsa-sha2-nistp521": 2,
        }.get(algorithm)
        if count is None:
            return False

        key_fields: list[bytes] = []
        for _ in range(count):
            field = read_string()
            if not field:
                return False
            key_fields.append(field)
        if offset != len(decoded):
            return False

        if algorithm == b"ssh-rsa":
            return int.from_bytes(key_fields[0], "big") >= 3 and len(key_fields[1]) >= 64
        if algorithm == b"ssh-ed25519":
            return len(key_fields[0]) == 32
        if algorithm == b"ssh-dss":
            return len(key_fields[0]) >= 64

        curve = algorithm.removeprefix(b"ecdsa-sha2-")
        point_length = {b"nistp256": 65, b"nistp384": 97, b"nistp521": 133}[curve]
        return (
            key_fields[0] == curve
            and key_fields[1].startswith(b"\x04")
            and len(key_fields[1]) == point_length
        )

    def rejection_for_source_value(
        self,
        candidate: DetectionCandidate,
        source_text: str | None,
        associated_names: tuple[str, ...],
    ) -> RejectionReason | None:
        value = candidate.match
        if self.is_ssh_public_key(value):
            return RejectionReason(
                kind=RejectionKind.PUBLIC_CRYPTO,
                name="Public",
                category="SSH key",
            )
        if candidate.detection_method is not DetectionMethod.ENTROPY:
            return None

        if self.is_public_payment_address(value):
            return RejectionReason(
                kind=RejectionKind.PUBLIC_CRYPTO,
                name="Public",
                category="payment address",
            )
        path = PurePath(candidate.location.locator)
        if source_text and self.is_darktable_processing_value(value, source_text, path):
            return RejectionReason(
                kind=RejectionKind.STRUCTURAL_VALUE,
                name="Darktable",
                category="image-processing parameters",
            )
        git_config = (
            path.name in {"gitconfig", ".gitconfig"}
            or path.parts[-2:] == (".git", "config")
        )
        if (
            git_config
            and any(name.replace("_", "").lower() == "signingkey" for name in associated_names)
            and GPG_KEY_ID_RE.fullmatch(value)
        ):
            return RejectionReason(
                kind=RejectionKind.STRUCTURAL_VALUE,
                name="Git signing key",
                category="key reference",
            )
        if source_text and self.is_code_reference(value, source_text, path):
            return RejectionReason(
                kind=RejectionKind.STRUCTURAL_VALUE,
                name="Code",
                category="identifier reference",
            )
        if source_text and self.is_commit_reference(value, source_text):
            return RejectionReason(
                kind=RejectionKind.STRUCTURAL_VALUE,
                name="Git commit",
                category="reference",
            )
        return None

    @staticmethod
    def lexical_subject_for_candidate(candidate: DetectionCandidate) -> str:
        if isinstance(candidate.fragment, PEMKeyFragment):
            return ""

        if isinstance(candidate.fragment, DBConnectionFragment):
            password_match = DB_PASSWORD_IN_URI_RE.search(candidate.match)
            return password_match.group(1) if password_match else ""

        return candidate.match

    def rejection_for_pem_key(self, pem_key: PEMKeyFragment) -> RejectionReason | None:
        if not pem_key.footer:
            return MISSING_PEM_FOOTER

        if not pem_key.body:
            return MISSING_PEM_BODY

        if pem_key.pem_analysis.disposition is PemDisposition.PUBLIC_ARTIFACT:
            return RejectionReason(
                kind=RejectionKind.PUBLIC_CRYPTO,
                name="Public",
                category=pem_key.pem_analysis.display_category
            )

        normalized_body = normalize_pem_body(pem_key.body)
        decoded_body = self.decode_base64_body(normalized_body)

        if decoded_body is None:
            return INVALID_PEM_BODY

        if len(decoded_body) < MIN_PEM_BODY_BYTES:
            return TOO_SHORT_PEM_BODY

        return None

    @staticmethod
    def decode_base64_body(body: str) -> bytes | None:
        if not body:
            return None

        if len(body) % 4 != 0:
            return None

        if not BASE64_STANDARD_VALUE_RE.fullmatch(body):
            return None

        try:
            body_decoded = base64.b64decode(body, validate=True)
            return body_decoded
        except (ValueError, BinasciiError):
            return None

    def rejection_for_db_password(
        self,
        password: str
    ) -> RejectionReason | None:
        if not password:
            return None

        if DB_CONN_PLACEHOLDER.pattern.search(password):
            return DB_CONN_PLACEHOLDER.reason

        for rejection_pattern in self.rejection_patterns:
            if (
                rejection_pattern.reason.kind is RejectionKind.PLACEHOLDER
                and rejection_pattern.pattern.search(password)
            ):
                return rejection_pattern.reason

        return None

    def rejection_for_generic_candidate(
        self,
        candidate: DetectionCandidate,
        hash_classification: HashValueClassification | None
    ) -> RejectionReason | None:
        string = candidate.match
        string_lower = string.lower()

        for rejection_pattern in self.rejection_patterns:
            if rejection_pattern.reason.kind is not RejectionKind.PLACEHOLDER:
                continue

            pattern = rejection_pattern.pattern

            if pattern.search(string_lower):
                if pattern.pattern == "test" and "sk_test" in string_lower:
                    continue

                return rejection_pattern.reason

        if hash_classification is not None:
            return hash_classification.rejection_reason

        for rejection_pattern in self.rejection_patterns:
            if rejection_pattern.reason.kind is RejectionKind.PLACEHOLDER:
                continue

            if rejection_pattern.pattern.search(string_lower):
                return rejection_pattern.reason

        return None

    def rejection_for_candidate(
        self,
        candidate: DetectionCandidate,
        lexical_subject: str,
        hash_classification: HashValueClassification | None,
        *,
        source_text: str | None = None,
        associated_names: tuple[str, ...] = (),
    ) -> RejectionReason | None:
        known_public = next((
            pattern.reason
            for pattern in self.known_public_patterns
            if pattern.pattern.fullmatch(candidate.match)
        ), None)
        fragment = candidate.fragment

        if isinstance(fragment, PEMKeyFragment):
            return self.rejection_for_pem_key(fragment) or known_public
        elif isinstance(fragment, DBConnectionFragment):
            if DB_EXAMPLE_URI_RE.fullmatch(candidate.match):
                return DB_CONN_PLACEHOLDER.reason
            if POSTGRES_LOCAL_DEFAULT_URI_RE.fullmatch(candidate.match):
                return RejectionReason(
                    kind=RejectionKind.PLACEHOLDER,
                    name="PostgreSQL",
                    category="local default credentials",
                    detail="postgres:postgres",
                )
            return self.rejection_for_db_password(lexical_subject) or known_public

        if candidate.finding_kind.id == "jwt_token":
            segments = candidate.match.split(".")
            if len(segments) == 3 and segments[2] == "signature":
                return RejectionReason(
                    kind=RejectionKind.PLACEHOLDER,
                    name="JWT signature",
                    category="placeholder",
                    detail=segments[2],
                )

        source_rejection = self.rejection_for_source_value(
            candidate, source_text, associated_names
        )
        if source_rejection is not None:
            return source_rejection

        rejection = self.rejection_for_generic_candidate(
            candidate,
            hash_classification
        )
        if rejection is not None and rejection.kind in {
            RejectionKind.PLACEHOLDER,
            RejectionKind.STRUCTURAL_PEM,
            RejectionKind.STRUCTURAL_VALUE,
            RejectionKind.PUBLIC_CRYPTO,
        }:
            return rejection

        if (
            candidate.detection_method is DetectionMethod.ENTROPY
            and source_text
            and self.is_abbreviated_jwt(candidate.match, source_text)
        ):
            return RejectionReason(
                kind=RejectionKind.STRUCTURAL_VALUE,
                name="Abbreviated",
                category="JWT example",
            )

        return known_public or rejection
