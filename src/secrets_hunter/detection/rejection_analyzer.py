import base64

from collections.abc import Iterable
from binascii import Error as BinasciiError

from secrets_hunter.detection.pem import (
    MIN_PEM_BODY_BYTES,
    PEM_BASE64_BODY_RE,
    PemDisposition
)
from secrets_hunter.detection.value_patterns import (
    DB_PASSWORD_IN_URI_RE,
    DB_PLACEHOLDER_RE
)
from secrets_hunter.detection.detectors.models import DetectionCandidate
from secrets_hunter.detection.fragmenter import DBConnectionFragment, PEMKeyFragment
from secrets_hunter.detection.hash_classification import HashValueClassification
from secrets_hunter.models import (
    RejectionKind,
    RejectionPattern,
    RejectionReason,
)


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


class CandidateRejectionAnalyzer:
    def __init__(
        self,
        rejection_patterns: Iterable[RejectionPattern]
    ) -> None:
        self.rejection_patterns = tuple(rejection_patterns)

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

        normalized_body = (
            pem_key.body
            .replace("\\r\\n", "\n")
            .replace("\\n", "\n")
            .replace("\\r", "\n")
        )
        normalized_body = "".join(normalized_body.split())

        decoded_body = self.decode_base64_body(normalized_body)

        if decoded_body is None:
            return INVALID_PEM_BODY

        if len(decoded_body) < MIN_PEM_BODY_BYTES:
            return TOO_SHORT_PEM_BODY

        if pem_key.pem_analysis.disposition is PemDisposition.PUBLIC_ARTIFACT:
            return RejectionReason(
                kind=RejectionKind.PUBLIC_CRYPTO,
                name="Public",
                category=pem_key.pem_analysis.display_category
            )

        return None

    @staticmethod
    def decode_base64_body(body: str) -> bytes | None:
        if not body:
            return None

        if len(body) % 4 != 0:
            return None

        if not PEM_BASE64_BODY_RE.fullmatch(body):
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
        hash_classification: HashValueClassification | None
    ) -> RejectionReason | None:
        fragment = candidate.fragment

        if isinstance(fragment, PEMKeyFragment):
            return self.rejection_for_pem_key(fragment)
        elif isinstance(fragment, DBConnectionFragment):
            return self.rejection_for_db_password(lexical_subject)

        return self.rejection_for_generic_candidate(
            candidate,
            hash_classification
        )
