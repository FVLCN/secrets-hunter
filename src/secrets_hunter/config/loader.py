from collections.abc import Mapping
from pathlib import Path

from secrets_hunter.config.specs import RejectionPatternSpec
from secrets_hunter.config.validation import RejectionPatternSpecValidator
from secrets_hunter.detection.assignment_resolver import (
    DEFAULT_ASSIGNMENT_PATTERN_SOURCES
)
from secrets_hunter.detection.regex import compile_regex
from secrets_hunter.immutability import frozen_mapping
from secrets_hunter.models import RejectionPattern, RejectionReason
from secrets_hunter.models.config import RuntimeConfig
from secrets_hunter.resources import LoadedToml, TomlTable, load_toml


REJECTION_PATTERNS_RESOURCE = "semantics/negative/rejection_patterns.toml"
SUPPORTED_USER_CONFIG_KEYS = frozenset({
    "ignore",
    "remove_ignore_files",
    "remove_ignore_extensions",
    "remove_ignore_dirs"
})


def require_table(
    value: object,
    key: str,
    file: str | Path
) -> TomlTable:
    if value is None:
        return {}

    if not isinstance(value, dict):
        raise ValueError(f"'{key}' must be a table in {file}")

    table: dict[str, object] = {}
    for table_key, item in value.items():
        if not isinstance(table_key, str):
            raise ValueError(f"'{key}' keys must be strings in {file}")
        table[table_key] = item

    return frozen_mapping(table)


def require_list(
    data: Mapping[str, object],
    key: str,
    file: str | Path
) -> list[object]:
    v = data.get(key) or []

    if not isinstance(v, list):
        raise ValueError(f"'{key}' must be a list in {file}")

    return list(v)


def require_string_list(
    data: Mapping[str, object],
    key: str,
    file: str | Path
) -> list[str]:
    v = require_list(data, key, file)
    strings: list[str] = []

    for i, item in enumerate(v):
        if not isinstance(item, str):
            raise ValueError(f"'{key}[{i}]' must be a string in {file}, got {type(item).__name__}")
        strings.append(item)

    return strings


def remove_from_list(lst: list[str], names: list[str]) -> list[str]:
    names_set = set(names)
    return [x for x in lst if x not in names_set]


def deduplicate_keep_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []

    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)

    return out


def reject_unsupported_user_config(
    data: Mapping[str, object],
    file: str | Path
) -> None:
    unsupported = sorted(set(data) - SUPPORTED_USER_CONFIG_KEYS)

    if unsupported:
        keys = ", ".join(unsupported)
        raise ValueError(
            f"Unsupported config keys in {file}: {keys}. "
            "User config currently supports only ignore settings."
        )


def load_runtime_config(user_configs: list[str | Path] | None = None) -> RuntimeConfig:
    """
    Loads packaged detection resources and ignore settings.
    User overlays are applied only to ignore settings, in the order provided.
    """
    overlay_files = [Path(p).expanduser().resolve() for p in (user_configs or [])]

    # aggregated (raw)
    rejection_specs_by_name: dict[str, RejectionPatternSpec] = {}
    assignment_pattern_sources = list(DEFAULT_ASSIGNMENT_PATTERN_SOURCES)
    ignore_files: list[str] = []
    ignore_ext: list[str] = []
    ignore_dirs: list[str] = []

    rejection_document = load_toml(fallback_resource=REJECTION_PATTERNS_RESOURCE)
    rejection_data = rejection_document.data
    rejection_source = rejection_document.source

    for item in require_list(rejection_data, "rejection_patterns", rejection_source):
        spec = RejectionPatternSpecValidator.parse(
            item,
            rejection_source
        )
        rejection_specs_by_name[spec.name] = spec

    ignore_documents: list[tuple[LoadedToml, bool]] = [
        (load_toml(fallback_resource="ignore.toml"), False)
    ]
    ignore_documents.extend(
        (load_toml(path), True)
        for path in overlay_files
    )

    for document, is_overlay in ignore_documents:
        data = document.data
        source = document.source

        if is_overlay:
            reject_unsupported_user_config(data, source)

        ignore_files = remove_from_list(
            ignore_files, require_string_list(data, "remove_ignore_files", source)
        )
        ignore_ext = remove_from_list(
            ignore_ext, require_string_list(data, "remove_ignore_extensions", source)
        )
        ignore_dirs = remove_from_list(
            ignore_dirs, require_string_list(data, "remove_ignore_dirs", source)
        )

        # ignore
        ig = require_table(data.get("ignore"), "ignore", source)
        ignore_files.extend(require_string_list(ig, "files", source))
        ignore_ext.extend(require_string_list(ig, "extensions", source))
        ignore_dirs.extend(require_string_list(ig, "dirs", source))

    # deduplication
    ignore_files = deduplicate_keep_order(ignore_files)
    ignore_ext = deduplicate_keep_order(ignore_ext)
    ignore_dirs = deduplicate_keep_order(ignore_dirs)

    # compile
    compiled_rejection_patterns = tuple(
        RejectionPattern(
            pattern=compile_regex(
                spec.pattern,
                spec.flags,
                source=f"rejection_patterns[{spec.name}]"
            ),
            reason=RejectionReason(
                kind=spec.kind,
                name=spec.name,
                category=spec.category
            )
        )
        for spec in rejection_specs_by_name.values()
    )

    compiled_assignment_patterns = tuple(
        compile_regex(p, source=f"hardcoded_assignment_pattern[{i}]")
        for i, p in enumerate(assignment_pattern_sources)
    )

    return RuntimeConfig(
        rejection_patterns=compiled_rejection_patterns,
        compiled_assignment_patterns=compiled_assignment_patterns,
        ignore_files=tuple(ignore_files),
        ignore_extensions=tuple(ignore_ext),
        ignore_dirs=tuple(ignore_dirs)
    )
