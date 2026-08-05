import re

from pathlib import PurePath

from secrets_hunter.detection.semantics.catalog import SemanticCatalog
from secrets_hunter.detection.semantics.corpus import CORPUS
from secrets_hunter.detection.semantics.lexical import LexicalAnalyzer
from secrets_hunter.detection.pem import PemDisposition
from secrets_hunter.models import DetectionMethod, RejectionKind

from .facts import FactId
from .models import SemanticInput, SemanticObservation


_TEXT_TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,63}")


class SemanticObservationBuilder:
    def __init__(
        self,
        catalog: SemanticCatalog,
        lexical_analyzer: LexicalAnalyzer | None = None
    ) -> None:
        self.catalog = catalog
        self.lexical_analyzer = lexical_analyzer or LexicalAnalyzer()

    def build(self, item: SemanticInput) -> SemanticObservation:
        associated_name = item.associated_name or ""
        value_analysis = item.value_analysis
        value = value_analysis.value
        detection_method = item.detection_method
        finding_kind = item.finding_kind
        file_path = item.file_path or ""
        lexical_subject = (
            value
            if item.lexical_subject is None
            else item.lexical_subject
        )
        lexical_analysis = self.lexical_analyzer.analyze(lexical_subject)
        value_kind = value_analysis.classification.kind
        hash_classification = value_analysis.hash_classification
        hash_rejection = (
            hash_classification.rejection_reason
            if hash_classification is not None
            else None
        )
        value_rejection = item.value_rejection or hash_rejection
        pem_analysis = item.pem_analysis
        catalog = self.catalog

        name_tokens = (
            catalog.tokens_for_name(associated_name)
            if associated_name
            else ()
        )
        name_roles = name_role_tokens(name_tokens) if associated_name else ()
        neutral_tokens = (
            neutral_identifier_tokens(name_tokens, catalog.vocabulary)
            if associated_name
            else ()
        )
        unknown_tokens = (
            unknown_identifier_tokens(name_tokens, catalog.vocabulary)
            if associated_name
            else ()
        )
        path = PurePath(file_path)
        file_extension = path.suffix.lower()
        file_extension_tokens = (
            (file_extension.removeprefix("."),)
            if file_extension
            else ()
        )
        english_words_in_value_tokens = (
            lexical_analysis.corpus_tokens
            if lexical_analysis.is_english_text
            else ()
        )
        finding_kind_tokens = tokens_from_text(
            finding_kind.id,
            catalog
        )
        rejection_tokens = tokens_from_text(
            " ".join(
                part
                for part in (
                    value_rejection.kind.value if value_rejection else None,
                    value_rejection.name if value_rejection else None,
                    value_rejection.category if value_rejection else None
                )
                if part
            ),
            catalog
        )
        public_crypto_shape_tokens = (
            pem_analysis.shape_tokens
            if pem_analysis is not None
            and pem_analysis.disposition is PemDisposition.PUBLIC_ARTIFACT
            and (
                value_rejection is None
                or value_rejection.kind is not RejectionKind.STRUCTURAL_PEM
            )
            else ()
        )
        hash_shape_tokens = (
            hash_classification.shape_tokens
            if hash_classification is not None
            else ()
        )
        value_shape_tokens = tuple(
            dict.fromkeys(public_crypto_shape_tokens + hash_shape_tokens)
        )
        value_entropy = value_analysis.entropy
        facts: set[FactId] = set()

        if not associated_name:
            facts.add(FactId.NO_ASSIGNMENT_CONTEXT)

        if detection_method is DetectionMethod.ENTROPY:
            facts.add(FactId.HIGH_ENTROPY)

        if detection_method is DetectionMethod.PATTERN:
            facts.add(FactId.KNOWN_PATTERN_MATCH)

        if public_crypto_shape_tokens:
            facts.add(FactId.PUBLIC_CRYPTO_ARTIFACT)

        if has_terminal_identifier_suffix(name_tokens):
            facts.add(FactId.TERMINAL_IDENTIFIER_SUFFIX)

        if unknown_tokens:
            facts.add(FactId.UNKNOWN_IDENTIFIER_CONTEXT)

        if english_words_in_value_tokens:
            facts.add(FactId.ENGLISH_WORDS_IN_VALUE)

        return SemanticObservation(
            finding_kind=finding_kind,
            value_kind=value_kind,
            name_tokens=name_tokens,
            name_role_tokens=name_roles,
            neutral_identifier_tokens=neutral_tokens,
            unknown_identifier_tokens=unknown_tokens,
            file_extension=file_extension,
            file_extension_tokens=file_extension_tokens,
            path_tokens=path_tokens(file_path, catalog),
            finding_kind_tokens=finding_kind_tokens,
            rejection_pattern_tokens=rejection_tokens,
            value_shape_tokens=value_shape_tokens,
            value_length_bucket=bucket_number(len(value), (0, 16, 24, 32, 40, 64, 128)),
            value_entropy_bucket=bucket_number(value_entropy, (0, 2, 3, 4, 5, 6)),
            english_words_in_value_tokens=english_words_in_value_tokens,
            value_rejection=value_rejection,
            provider_pattern_id=item.provider_pattern_id,
            facts=frozenset(facts)
        )


def name_role_tokens(name_tokens: tuple[str, ...]) -> tuple[str, ...]:
    if name_tokens == ("id",):
        return ("exact_identifier_name",)

    if has_terminal_identifier_suffix(name_tokens):
        return ("terminal_identifier_suffix",)

    return ()


def has_terminal_identifier_suffix(name_tokens: tuple[str, ...]) -> bool:
    return len(name_tokens) > 1 and name_tokens[-1] == "id"


def bucket_number(value: float, boundaries: tuple[float, ...]) -> str:
    for boundary in boundaries:
        if value <= boundary:
            return f"le_{boundary:g}"

    return f"gt_{boundaries[-1]:g}"


def path_tokens(file_path: str, catalog: SemanticCatalog) -> tuple[str, ...]:
    path = PurePath(file_path)
    parts: list[str] = []

    for part in path.parts:
        if part == path.name and path.suffix:
            parts.append(path.stem)
        else:
            parts.append(str(part))

    return tokens_from_text(" ".join(parts or [file_path]), catalog)


def neutral_identifier_tokens(
    name_tokens: tuple[str, ...],
    concept_vocabulary: frozenset[str]
) -> tuple[str, ...]:
    return tuple(
        token
        for token in name_tokens
        if len(token) > 2
        and token in CORPUS
        and token not in concept_vocabulary
    )


def unknown_identifier_tokens(
    name_tokens: tuple[str, ...],
    concept_vocabulary: frozenset[str]
) -> tuple[str, ...]:
    return tuple(
        token
        for token in name_tokens
        if len(token) > 2
        and any(char.isalpha() for char in token)
        and token not in CORPUS
        and token not in concept_vocabulary
    )


def tokens_from_text(text: str, catalog: SemanticCatalog) -> tuple[str, ...]:
    tokens: list[str] = []

    for raw_token in _TEXT_TOKEN_RE.findall(text or ""):
        tokens.extend(catalog.tokens_for_name(raw_token))

    return tuple(dict.fromkeys(tokens))
