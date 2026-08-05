import re

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from secrets_hunter.detection.value_patterns import VALUE_BOUNDARY_CHARS
from secrets_hunter.immutability import frozen_mapping


DEFAULT_ASSIGNMENT_PATTERN_SOURCES = (
    # Assignment operators: a = "secret" or "a" = "secret" or key => "value" or key =: "value" etc.
    r'''["']?([a-zA-Z_][a-zA-Z0-9_]*)["']?\s*(?:==|=|:=|=>|=:)\s*["'`]([^"'`]+)["'`]''',
    # Colon key-value pairs: a: "secret" or "a": "secret" (JSON, YAML)
    r'''["']?([a-zA-Z_][a-zA-Z0-9_]*)["']?\s*:\s*["']([^"']+)["']''',
    # token = abc123def456xyz789 (unquoted)
    r'''["']?([a-zA-Z_][a-zA-Z0-9_]*)["']?\s*[:=]\s*([^\s,}]+)''',
    # Tuple/function assignments: (password, "secret") or ("user", 'pass') or ('key', "value")
    r'''\(\s*["']?([^"',\s()]+)["']?\s*,\s*["']([^"']+)["']\s*\)?''',
    # Docker ENV statements: ENV API_KEY "secret123" or ENV PASSWORD secret
    r'''ENV\s+([A-Z_][A-Z0-9_]*)\s+["']?([^"'\n]+)["']?''',
    # C/C++ preprocessor defines: #define API_KEY "secret123"
    r'''#define\s+([A-Z_][A-Z0-9_]*)\s+["']([^"']+)["']''',
    # Python with type hints: api_key: str | None = "secret123"
    r'''([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*[^=\n]+\s*=\s*["']([^"']+)["']'''
)


@dataclass(frozen=True)
class AssignmentContext:
    associated_names_by_value: Mapping[str, tuple[str, ...]]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "associated_names_by_value",
            frozen_mapping({
                value: tuple(associated_names)
                for value, associated_names in self.associated_names_by_value.items()
            })
        )

    def associated_names_for(
        self,
        *,
        match: str,
        candidate_context: str
    ) -> tuple[str, ...]:
        normalized_match = match.strip().strip(VALUE_BOUNDARY_CHARS)
        associated_names = (
            self.associated_names_by_value.get(match)
            or self.associated_names_by_value.get(normalized_match)
        )

        if associated_names:
            return associated_names

        if not match or not candidate_context:
            return ()

        match_probe = match[:min(len(match), 24)]
        match_index = candidate_context.find(match_probe)

        if match_index < 0:
            return ()

        for assigned_value, associated_names in self.associated_names_by_value.items():
            if not assigned_value or len(assigned_value) < 4:
                continue

            if match_probe in assigned_value or match in assigned_value:
                return associated_names

            assigned_index = candidate_context.find(assigned_value)

            if 0 <= assigned_index <= match_index:
                return associated_names

        return ()


class AssignmentResolver:
    def __init__(
        self,
        compiled_patterns: Iterable[re.Pattern[str]],
    ) -> None:
        self.compiled_patterns = tuple(compiled_patterns)

    def build(self, source: str) -> AssignmentContext:
        associated_names_by_value: dict[str, set[str]] = {}

        for pattern in self.compiled_patterns:
            for match in pattern.finditer(source):
                associated_name = match.group(1)
                value = match.group(2).strip().strip(VALUE_BOUNDARY_CHARS)
                associated_names_by_value.setdefault(value, set()).add(
                    associated_name
                )

                for separator in ("=", ":"):
                    if separator not in value:
                        continue

                    right_hand_side = (
                        value.split(separator, 1)[1]
                        .strip(VALUE_BOUNDARY_CHARS)
                        .lstrip("=")
                    )

                    if right_hand_side and right_hand_side != value:
                        associated_names_by_value.setdefault(
                            right_hand_side,
                            set()
                        ).add(associated_name)

                    break

        return AssignmentContext(
            associated_names_by_value={
                value: tuple(sorted(associated_names))
                for value, associated_names in associated_names_by_value.items()
            }
        )
