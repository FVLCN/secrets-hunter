from abc import ABC, abstractmethod
from dataclasses import dataclass, replace
from typing import Self


def _require_non_empty(value: str, field_name: str) -> None:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string")

    if not value.strip():
        raise ValueError(f"{field_name} must not be empty")


@dataclass(frozen=True, kw_only=True)
class SourceLocation(ABC):
    line: int

    def __post_init__(self) -> None:
        if isinstance(self.line, bool) or not isinstance(self.line, int):
            raise TypeError("line must be an integer")

        if self.line < 1:
            raise ValueError("line must be greater than zero")

    @property
    @abstractmethod
    def locator(self) -> str:
        ...

    def at_line(self, line: int) -> Self:
        return replace(self, line=line)


@dataclass(frozen=True, kw_only=True)
class FileLocation(SourceLocation):
    path: str

    def __post_init__(self) -> None:
        super().__post_init__()
        _require_non_empty(self.path, "path")

    @property
    def locator(self) -> str:
        return self.path


@dataclass(frozen=True, kw_only=True)
class GitLocation(SourceLocation):
    path: str
    commit_sha: str

    def __post_init__(self) -> None:
        super().__post_init__()
        _require_non_empty(self.path, "path")
        _require_non_empty(self.commit_sha, "commit_sha")

    @property
    def locator(self) -> str:
        return self.path


@dataclass(frozen=True, kw_only=True)
class HttpLocation(SourceLocation):
    requested_url: str
    effective_url: str

    def __post_init__(self) -> None:
        super().__post_init__()
        _require_non_empty(self.requested_url, "requested_url")
        _require_non_empty(self.effective_url, "effective_url")

    @property
    def locator(self) -> str:
        return self.effective_url


@dataclass(frozen=True, kw_only=True)
class TextLocation(SourceLocation):
    label: str

    def __post_init__(self) -> None:
        super().__post_init__()
        _require_non_empty(self.label, "label")

    @property
    def locator(self) -> str:
        return self.label
