from dataclasses import dataclass
from pathlib import Path
from typing import Never


@dataclass(frozen=True)
class TextSource:
    content: str
    name: str = "<memory>"


@dataclass(frozen=True)
class FilesystemSource:
    target: str | Path


@dataclass(frozen=True)
class GitHistorySource:
    target: str | Path
    revset: str
    max_count: int | None = None


@dataclass(frozen=True)
class DomainSource:
    domain: str
    skip_tls_verify: bool = False


type ScanSource = (
    TextSource
    | FilesystemSource
    | GitHistorySource
    | DomainSource
)


def unsupported_scan_source(source: Never) -> Never:
    raise TypeError(f"Unsupported scan source: {type(source).__name__}")
