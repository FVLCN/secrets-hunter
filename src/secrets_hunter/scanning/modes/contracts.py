from collections.abc import Callable, Mapping
from dataclasses import dataclass

from secrets_hunter.immutability import frozen_mapping
from secrets_hunter.scanning.content_validator import TextContentValidator
from secrets_hunter.scanning.path_filter import PathFilter
from secrets_hunter.scanning.scanner import BaseScanner
from secrets_hunter.scanning.session import ScanSession
from secrets_hunter.scanning.text_reader import SourceTextReader

from .sources import ScanSource


type SourceParameter = str | int | bool | None
type SourceParameters = Mapping[str, SourceParameter]


@dataclass(frozen=True)
class ScannerContext:
    session: ScanSession
    content_validator: TextContentValidator
    source_text_reader: SourceTextReader
    path_filter: PathFilter


@dataclass(frozen=True)
class ScanSourceDescription:
    kind: str
    parameters: SourceParameters

    def __post_init__(self) -> None:
        if not isinstance(self.kind, str):
            raise TypeError("scan source kind must be a string")

        if not self.kind.strip():
            raise ValueError("scan source kind must not be empty")

        if not isinstance(self.parameters, Mapping):
            raise TypeError("scan source parameters must be a mapping")

        parameters = dict(self.parameters)
        if "kind" in parameters:
            raise ValueError("scan source parameters must not contain 'kind'")

        for name, value in parameters.items():
            if not isinstance(name, str) or not name:
                raise TypeError(
                    "scan source parameter names must be non-empty strings"
                )

            if value is not None and not isinstance(
                value,
                (str, int, bool)
            ):
                raise TypeError(
                    f"unsupported scan source parameter {name!r}: "
                    f"{type(value).__name__}"
                )

        object.__setattr__(
            self,
            "parameters",
            frozen_mapping(parameters)
        )


type SourceValidator[S: ScanSource] = Callable[[S], None]
type ScannerFactory[S: ScanSource] = Callable[
    [S, ScannerContext],
    BaseScanner
]
type SourceDescriber[S: ScanSource] = Callable[[S], SourceParameters]


@dataclass(frozen=True)
class ScanModeDefinition[S: ScanSource]:
    mode_id: str
    source_type: type[S]
    validate_source: SourceValidator[S]
    create_scanner: ScannerFactory[S]
    describe_source: SourceDescriber[S]

    def __post_init__(self) -> None:
        if not isinstance(self.mode_id, str):
            raise TypeError("scan mode ID must be a string")

        if not self.mode_id.strip():
            raise ValueError("scan mode ID must not be empty")

        if (
            not isinstance(self.source_type, type)
            or not issubclass(self.source_type, ScanSource)
        ):
            raise TypeError("source_type must be a ScanSource type")

        for name, operation in (
            ("validate_source", self.validate_source),
            ("create_scanner", self.create_scanner),
            ("describe_source", self.describe_source)
        ):
            if not callable(operation):
                raise TypeError(f"{name} must be callable")
