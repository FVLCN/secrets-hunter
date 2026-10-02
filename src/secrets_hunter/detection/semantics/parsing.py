from collections.abc import Mapping

from secrets_hunter.immutability import frozen_mapping
from secrets_hunter.resources import TomlTable


def normalize_token(value: str) -> str:
    return value.strip().lower().replace("-", "_")


def require_string(value: object, key: str, file_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"'{key}' must be a non-empty string in {file_name}")

    return value


def require_string_or_empty(value: object, key: str, file_name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"'{key}' must be a string in {file_name}")

    return value


def require_string_list(
    data: Mapping[str, object],
    key: str,
    file_name: str
) -> tuple[str, ...]:
    value = data.get(key) or []

    if not isinstance(value, list):
        raise ValueError(f"'{key}' must be a list of strings in {file_name}")

    strings: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise ValueError(f"'{key}' must be a list of strings in {file_name}")
        strings.append(item)

    return tuple(strings)


def require_table(value: object, key: str, file_name: str) -> TomlTable:
    if not isinstance(value, dict):
        raise ValueError(f"'{key}' must be a table in {file_name}")

    table: dict[str, object] = {}
    for table_key, item in value.items():
        if not isinstance(table_key, str):
            raise ValueError(f"'{key}' keys must be strings in {file_name}")
        table[table_key] = item

    return frozen_mapping(table)
