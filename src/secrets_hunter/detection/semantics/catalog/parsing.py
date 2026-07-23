from collections.abc import Mapping
from dataclasses import fields, is_dataclass
from typing import get_type_hints


def _load_number_config[_NumberConfig](
    data: Mapping[str, object],
    config_type: type[_NumberConfig],
    section: str,
    source: str
) -> _NumberConfig:
    if not is_dataclass(config_type):
        raise TypeError(f"{config_type!r} must be a dataclass type")

    config_fields = fields(config_type)
    type_hints = get_type_hints(config_type)
    expected = {field.name for field in config_fields}
    actual = set(data)
    missing = sorted(expected - actual)
    unknown = sorted(actual - expected)

    if missing:
        raise ValueError(
            f"Missing policy fields in {source}: "
            f"{', '.join(f'{section}.{name}' for name in missing)}"
        )

    if unknown:
        raise ValueError(
            f"Unknown policy fields in {source}: "
            f"{', '.join(f'{section}.{name}' for name in unknown)}"
        )

    values: dict[str, object] = {}

    for field in config_fields:
        field_name = field.name
        field_path = f"{section}.{field_name}"
        field_type = type_hints[field_name]
        value = data[field_name]

        if is_dataclass(field_type):
            if not isinstance(value, dict):
                raise ValueError(f"'{field_path}' must be a table in {source}")

            values[field_name] = _load_number_config(
                value,
                field_type,
                field_path,
                source
            )
            continue

        if field_type is int:
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f"'{field_path}' must be an integer in {source}")

            values[field_name] = value
            continue

        if field_type is float:
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"'{field_path}' must be a number in {source}")

            values[field_name] = float(value)
            continue

        raise TypeError(
            f"Unsupported policy field type {field_type!r} for {field_path}"
        )

    return config_type(**values)
