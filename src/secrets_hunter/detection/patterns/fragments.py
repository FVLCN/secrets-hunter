import re


IDENTIFIER_RE = re.compile(
    r"^(?:[a-z][a-z0-9]*(?:_[a-z0-9]+)*|[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*|[a-z][a-zA-Z0-9]*)$"
)
QUOTED_STRING_RE = re.compile(
    r'"((?:\\.|[^"\\]){5,})"|\'((?:\\.|[^\'\\]){5,})\'|`((?:\\.|[^`\\]){5,})`'
)


def compile_chunk_regex(min_token_length: int) -> re.Pattern[str]:
    return re.compile(rf"\S{{{min_token_length},}}")
