import re


_ACRONYM_BOUNDARY = re.compile(r"([A-Z]+)([A-Z][a-z])")
_LOWER_OR_DIGIT_TO_UPPER_BOUNDARY = re.compile(r"([a-z\d])([A-Z])")
_NON_ALPHANUMERIC = re.compile(r"[^A-Za-z0-9]+")


def split_identifier(value: str) -> tuple[str, ...]:
    value = value.strip()

    if not value:
        return ()

    value = _ACRONYM_BOUNDARY.sub(r"\1_\2", value)
    value = _LOWER_OR_DIGIT_TO_UPPER_BOUNDARY.sub(r"\1_\2", value)
    parts = _NON_ALPHANUMERIC.split(value)

    return tuple(part.lower() for part in parts if part)
