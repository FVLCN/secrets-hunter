from secrets_hunter.models import (
    FileLocation,
    GitLocation,
    HttpLocation,
    SourceLocation,
    TextLocation
)


def format_source_location(location: SourceLocation) -> str:
    return f"{location.locator}:{location.line}"


def source_location_kind(location: SourceLocation) -> str:
    if isinstance(location, FileLocation):
        return "file"

    if isinstance(location, GitLocation):
        return "git"

    if isinstance(location, HttpLocation):
        return "http"

    if isinstance(location, TextLocation):
        return "text"

    raise TypeError(
        f"Unsupported source location: {type(location).__name__}"
    )


def source_location_to_dict(
    location: SourceLocation
) -> dict[str, object]:
    if isinstance(location, FileLocation):
        return {
            "path": location.path,
            "line": location.line
        }

    if isinstance(location, GitLocation):
        return {
            "path": location.path,
            "commit_sha": location.commit_sha,
            "line": location.line
        }

    if isinstance(location, HttpLocation):
        return {
            "requested_url": location.requested_url,
            "effective_url": location.effective_url,
            "line": location.line
        }

    if isinstance(location, TextLocation):
        return {
            "label": location.label,
            "line": location.line
        }

    raise TypeError(
        f"Unsupported source location: {type(location).__name__}"
    )
