from dataclasses import dataclass
from pathlib import Path


class ScanSource:
    pass


@dataclass(frozen=True)
class TextSource(ScanSource):
    content: str
    name: str = "<memory>"


@dataclass(frozen=True)
class FilesystemSource(ScanSource):
    target: str | Path


@dataclass(frozen=True)
class GitHistorySource(ScanSource):
    target: str | Path
    revset: str
    max_count: int | None = None


@dataclass(frozen=True)
class DomainSource(ScanSource):
    domain: str
    skip_tls_verify: bool = False
