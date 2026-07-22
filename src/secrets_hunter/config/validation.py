import math
import os
from pathlib import Path

from secrets_hunter.models import RejectionKind

from .settings import (
    B64_ENTROPY_MAX,
    DEFAULT_SCAN_OPTIONS,
    HEX_ENTROPY_MAX,
    MAX_WORKERS_MULTIPLIER,
    FindingOutputOptions,
    ScanOptions
)
from .specs import RejectionPatternSpec


class RejectionPatternSpecValidator:
    REQUIRED_FIELDS = ("name", "pattern", "category")

    @classmethod
    def parse(
        cls,
        value: object,
        source: str | Path
    ) -> RejectionPatternSpec:
        if not isinstance(value, dict):
            raise ValueError(
                f"'rejection_patterns' items must be tables in {source}: {value!r}"
            )

        fields: dict[str, object] = {}
        for key, field_value in value.items():
            if not isinstance(key, str):
                raise ValueError(
                    f"'rejection_patterns' keys must be strings in {source}"
                )
            fields[key] = field_value

        missing = [name for name in cls.REQUIRED_FIELDS if name not in fields]
        if missing:
            raise ValueError(
                f"'rejection_patterns' item in {source} missing fields "
                f"{', '.join(missing)}: {value!r}"
            )

        name = cls._require_string(fields["name"], "name", source)
        pattern = cls._require_string(fields["pattern"], "pattern", source)
        category = cls._require_string(fields["category"], "category", source)
        flags = cls._require_flags(fields.get("flags"), source)
        kind = cls._require_kind(fields.get("kind"), source)

        return RejectionPatternSpec(
            name=name,
            pattern=pattern,
            category=category,
            flags=flags,
            kind=kind
        )

    @staticmethod
    def _require_string(
        value: object,
        field: str,
        source: str | Path
    ) -> str:
        if not isinstance(value, str) or not value:
            raise ValueError(
                f"'rejection_patterns.{field}' must be a non-empty string in {source}"
            )
        return value

    @staticmethod
    def _require_flags(
        value: object,
        source: str | Path
    ) -> tuple[str, ...]:
        if value is None:
            return ()
        if not isinstance(value, list):
            raise ValueError(
                f"'rejection_patterns.flags' must be a list of strings in {source}"
            )

        flags: list[str] = []
        for flag in value:
            if not isinstance(flag, str):
                raise ValueError(
                    f"'rejection_patterns.flags' must be a list of strings in {source}"
                )
            flags.append(flag)

        return tuple(flags)

    @staticmethod
    def _require_kind(value: object, source: str | Path) -> RejectionKind:
        if value is None:
            return RejectionKind.GENERIC
        if not isinstance(value, str):
            raise ValueError(
                f"'rejection_patterns.kind' must be a string in {source}"
            )
        try:
            return RejectionKind(value.strip().lower().replace("-", "_"))
        except ValueError as error:
            expected = ", ".join(kind.value for kind in RejectionKind)
            raise ValueError(
                f"Unknown rejection kind {value!r} in {source}; "
                f"expected one of: {expected}"
            ) from error


class ScanOptionsValidator:
    @staticmethod
    def validate(options: ScanOptions) -> None:
        if not isinstance(options, ScanOptions):
            raise TypeError("scan_options must be a ScanOptions instance")

        if (
            isinstance(options.hex_entropy_threshold, bool)
            or not isinstance(options.hex_entropy_threshold, (int, float))
        ):
            raise TypeError("hex_entropy_threshold must be a number")

        if not 0.0 <= options.hex_entropy_threshold <= HEX_ENTROPY_MAX:
            raise ValueError(
                "hex_entropy_threshold must be between "
                f"0.0 and {HEX_ENTROPY_MAX}"
            )

        if (
            isinstance(options.b64_entropy_threshold, bool)
            or not isinstance(options.b64_entropy_threshold, (int, float))
        ):
            raise TypeError("b64_entropy_threshold must be a number")

        if not 0.0 <= options.b64_entropy_threshold <= B64_ENTROPY_MAX:
            raise ValueError(
                "b64_entropy_threshold must be between "
                f"0.0 and {B64_ENTROPY_MAX}"
            )

        if (
            isinstance(options.min_string_length, bool)
            or not isinstance(options.min_string_length, int)
        ):
            raise TypeError("min_string_length must be an integer")

        if options.min_string_length <= 0:
            raise ValueError("min_string_length must be greater than zero")

        if isinstance(options.max_workers, bool) or not isinstance(options.max_workers, int):
            raise TypeError("max_workers must be an integer")

        if options.max_workers <= 0:
            raise ValueError("max_workers must be greater than zero")

        max_workers = max(
            DEFAULT_SCAN_OPTIONS.max_workers,
            (os.cpu_count() or 1) * MAX_WORKERS_MULTIPLIER
        )
        if options.max_workers > max_workers:
            raise ValueError(f"max_workers cannot exceed {max_workers}")

        if (
            isinstance(options.max_source_bytes, bool)
            or not isinstance(options.max_source_bytes, int)
        ):
            raise TypeError("max_source_bytes must be an integer")

        if options.max_source_bytes <= 0:
            raise ValueError("max_source_bytes must be greater than zero")

        if (
            isinstance(options.source_timeout_seconds, bool)
            or not isinstance(options.source_timeout_seconds, (int, float))
        ):
            raise TypeError("source_timeout_seconds must be a number")

        if (
            not math.isfinite(float(options.source_timeout_seconds))
            or options.source_timeout_seconds <= 0
        ):
            raise ValueError("source_timeout_seconds must be finite and greater than zero")


class FindingOutputOptionsValidator:
    @staticmethod
    def validate(options: FindingOutputOptions) -> None:
        if not isinstance(options, FindingOutputOptions):
            raise TypeError(
                "output_options must be a FindingOutputOptions instance"
            )

        if isinstance(options.min_confidence, bool) or not isinstance(
            options.min_confidence,
            int
        ):
            raise TypeError("min_confidence must be an integer")

        if not 0 <= options.min_confidence <= 100:
            raise ValueError("min_confidence must be between 0 and 100")

        if not isinstance(options.reveal_findings, bool):
            raise TypeError("reveal_findings must be a boolean")

        if not isinstance(options.truncate_long_matches, bool):
            raise TypeError("truncate_long_matches must be a boolean")
