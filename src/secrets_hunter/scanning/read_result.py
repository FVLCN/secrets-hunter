from dataclasses import dataclass


@dataclass(frozen=True)
class SourceBytes:
    content: bytes


@dataclass(frozen=True)
class SourceMissing:
    pass


@dataclass(frozen=True)
class SourceCancelled:
    pass


@dataclass(frozen=True)
class SourceReadFailure:
    message: str


type SourceReadResult = (
    SourceBytes
    | SourceMissing
    | SourceCancelled
    | SourceReadFailure
)
