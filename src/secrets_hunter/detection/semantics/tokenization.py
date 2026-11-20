from functools import lru_cache

from secrets_hunter.detection.patterns.text import (
    ACRONYM_BOUNDARY_RE,
    LOWER_OR_DIGIT_TO_UPPER_BOUNDARY_RE,
    NON_ALPHANUMERIC_RE,
)


_MAX_CACHED_IDENTIFIER_CHARS = 256


def _split_identifier_uncached(value: str) -> tuple[str, ...]:
    value = ACRONYM_BOUNDARY_RE.sub(r"\1_\2", value)
    value = LOWER_OR_DIGIT_TO_UPPER_BOUNDARY_RE.sub(r"\1_\2", value)
    parts = NON_ALPHANUMERIC_RE.split(value)

    return tuple(part.lower() for part in parts if part)


_cached_split_identifier = lru_cache(maxsize=4096)(_split_identifier_uncached)


def split_identifier(value: str) -> tuple[str, ...]:
    value = value.strip()

    if not value:
        return ()

    if len(value) > _MAX_CACHED_IDENTIFIER_CHARS:
        return _split_identifier_uncached(value)

    return _cached_split_identifier(value)
