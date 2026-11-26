import re

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol

from secrets_hunter.models import ValueKind


class EntropyFamily(StrEnum):
    HEX = "hex"
    BASE64 = "base64"


@dataclass(frozen=True, slots=True)
class ValueClassification:
    kind: ValueKind
    entropy_family: EntropyFamily | None = None


@dataclass(frozen=True, slots=True)
class ValueKindSpec:
    kind: ValueKind
    required_patterns: tuple[re.Pattern[str], ...]
    entropy_family: EntropyFamily | None = None
    classification: ValueClassification = field(init=False, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "required_patterns",
            tuple(self.required_patterns)
        )
        object.__setattr__(
            self,
            "classification",
            ValueClassification(self.kind, self.entropy_family)
        )

    def matches(self, value: str) -> bool:
        for pattern in self.required_patterns:
            if pattern.fullmatch(value) is None:
                return False

        return True


class ValueClassifier(Protocol):
    def classify(self, value: str) -> ValueClassification:
        ...


@dataclass(frozen=True)
class ValueClassificationPlan:
    specs: tuple[ValueKindSpec, ...]
    default_kind: ValueKind = ValueKind.GENERIC
    _empty: ValueClassification = field(init=False, repr=False)
    _default: ValueClassification = field(init=False, repr=False)
    _fast_classifier: re.Pattern[str] | None = field(init=False, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "specs", tuple(self.specs))
        object.__setattr__(
            self,
            "_empty",
            ValueClassification(ValueKind.EMPTY)
        )
        object.__setattr__(
            self,
            "_default",
            ValueClassification(self.default_kind)
        )
        object.__setattr__(
            self,
            "_fast_classifier",
            _compile_fast_classifier(self.specs)
        )

    def classify(self, value: str) -> ValueClassification:
        normalized = value or ""

        if not normalized:
            return self._empty

        if self._fast_classifier is not None:
            match = self._fast_classifier.fullmatch(normalized)

            if match is None or match.lastindex is None:
                return self._default

            return self.specs[match.lastindex - 1].classification

        for spec in self.specs:
            if spec.matches(normalized):
                return spec.classification

        return self._default


def _compile_fast_classifier(
    specs: tuple[ValueKindSpec, ...]
) -> re.Pattern[str] | None:
    if not specs:
        return None

    patterns = tuple(
        pattern
        for spec in specs
        for pattern in spec.required_patterns
    )
    if any(pattern.groups for pattern in patterns):
        return None

    if any(pattern.flags != re.UNICODE for pattern in patterns):
        return None

    alternatives: list[str] = []

    for spec in specs:
        if len(spec.required_patterns) == 1:
            rule_pattern = spec.required_patterns[0].pattern
        else:
            lookaheads = "".join(
                rf"(?=(?:{pattern.pattern})\Z)"
                for pattern in spec.required_patterns
            )
            rule_pattern = rf"{lookaheads}[\s\S]*"

        alternatives.append(f"({rule_pattern})")

    try:
        return re.compile("|".join(alternatives))
    except re.error:
        return None
