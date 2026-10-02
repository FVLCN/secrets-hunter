import re

from collections.abc import Iterable


REGEX_FLAG_VALUES: dict[str, int] = {
    "IGNORECASE": re.IGNORECASE,
    "MULTILINE": re.MULTILINE,
    "DOTALL": re.DOTALL,
    "VERBOSE": re.VERBOSE,
    "ASCII": re.ASCII
}


def compile_regex(
    pattern: str,
    flags: Iterable[str] | None = None,
    *,
    source: str = ""
) -> re.Pattern[str]:
    compiled_flags = 0

    for name in flags or ():
        if name not in REGEX_FLAG_VALUES:
            where = f" in {source}" if source else ""
            raise ValueError(f"Unknown regex flag '{name}'{where}")

        compiled_flags |= REGEX_FLAG_VALUES[name]

    try:
        return re.compile(pattern, compiled_flags)
    except re.error as error:
        where = f" in {source}" if source else ""
        raise ValueError(f"Invalid regex pattern{where}: {error}") from error
