import json
import tomllib

from collections.abc import Mapping
from dataclasses import dataclass
from importlib.resources import files as resource_files
from importlib.resources.abc import Traversable
from pathlib import Path

from secrets_hunter.immutability import frozen_mapping


PACKAGED_RESOURCE_PACKAGE = "secrets_hunter.config"

type TomlTable = Mapping[str, object]
type JsonScalar = None | bool | int | float | str
type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]
type JsonObject = dict[str, JsonValue]
type FrozenJsonValue = (
    JsonScalar
    | tuple[FrozenJsonValue, ...]
    | Mapping[str, FrozenJsonValue]
)
type FrozenJsonObject = Mapping[str, FrozenJsonValue]


def empty_frozen_json_object() -> FrozenJsonObject:
    return frozen_mapping({})


@dataclass(frozen=True)
class LoadedToml:
    data: TomlTable
    source: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "data",
            frozen_mapping(self.data)
        )


def _string_keyed_table(value: object, source: str) -> TomlTable:
    if not isinstance(value, dict):
        raise ValueError(f"Configuration root must be a table in {source}")

    table: dict[str, object] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise ValueError(f"Configuration keys must be strings in {source}")
        table[key] = item

    return frozen_mapping(table)


def _normalize_json_value(value: object, source: str) -> JsonValue:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value

    if isinstance(value, list):
        return [_normalize_json_value(item, source) for item in value]

    if isinstance(value, dict):
        normalized: JsonObject = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"JSON object keys must be strings in {source}")
            normalized[key] = _normalize_json_value(item, source)
        return normalized

    raise ValueError(
        f"Unsupported JSON value {type(value).__name__} in {source}"
    )


def normalize_json_object(value: object, source: str) -> JsonObject:
    normalized = _normalize_json_value(value, source)

    if not isinstance(normalized, dict):
        raise ValueError(f"JSON root must be an object in {source}")

    return normalized


def freeze_json_value(value: object, source: str) -> FrozenJsonValue:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value

    if isinstance(value, (list, tuple)):
        return tuple(freeze_json_value(item, source) for item in value)

    if isinstance(value, Mapping):
        frozen: dict[str, FrozenJsonValue] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"JSON object keys must be strings in {source}")
            frozen[key] = freeze_json_value(item, source)
        return frozen_mapping(frozen)

    raise ValueError(
        f"Unsupported JSON value {type(value).__name__} in {source}"
    )


def freeze_json_object(
    value: Mapping[str, object],
    source: str
) -> FrozenJsonObject:
    frozen = freeze_json_value(value, source)
    if not isinstance(frozen, Mapping):
        raise ValueError(f"JSON root must be an object in {source}")
    return frozen


def thaw_json_value(value: FrozenJsonValue) -> JsonValue:
    if isinstance(value, Mapping):
        return {
            key: thaw_json_value(item)
            for key, item in value.items()
        }

    if isinstance(value, tuple):
        return [thaw_json_value(item) for item in value]

    return value


def packaged_resource(resource_name: str) -> Traversable:
    parts = resource_name.split("/")

    if (
        not resource_name
        or resource_name.startswith("/")
        or "\\" in resource_name
        or any(not part or part in {".", ".."} for part in parts)
    ):
        raise ValueError(f"Invalid config resource name: {resource_name!r}")

    resource = resource_files(PACKAGED_RESOURCE_PACKAGE)

    for part in parts:
        resource = resource / part

    return resource


def _read_text(document: Path | Traversable, source: str) -> str:
    try:
        return document.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"Config source not found: {source}") from exc
    except OSError as exc:
        raise type(exc)(f"Cannot read config source {source}: {exc}") from exc


def load_toml(
    path: str | Path | None = None,
    *,
    fallback_resource: str | None = None
) -> LoadedToml:
    if path is not None:
        document: Path | Traversable = Path(path).expanduser()
        source = str(document)
    elif fallback_resource is not None:
        document = packaged_resource(fallback_resource)
        source = fallback_resource
    else:
        raise ValueError("TOML loading requires a path or fallback resource")

    try:
        raw_data: object = tomllib.loads(_read_text(document, source))
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f"Invalid TOML in {source}: {exc}") from exc

    return LoadedToml(
        data=_string_keyed_table(raw_data, source),
        source=source
    )


def load_json_resource(resource_name: str) -> JsonObject:
    resource = packaged_resource(resource_name)

    try:
        raw_data: object = json.loads(_read_text(resource, resource_name))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in {resource_name}: {exc}") from exc

    return normalize_json_object(raw_data, resource_name)


def read_resource_bytes(resource_name: str) -> bytes:
    resource = packaged_resource(resource_name)

    try:
        return resource.read_bytes()
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"Config source not found: {resource_name}") from exc
    except OSError as exc:
        raise type(exc)(f"Cannot read config source {resource_name}: {exc}") from exc
