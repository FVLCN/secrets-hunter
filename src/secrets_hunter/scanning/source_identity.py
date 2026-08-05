from dataclasses import dataclass
from pathlib import Path

from secrets_hunter.models import (
    FileLocation,
    GitLocation,
    HttpLocation,
    SourceLocation,
    TextLocation
)


@dataclass(frozen=True)
class SourceIdentity:
    display_label: str
    location: SourceLocation

    @classmethod
    def for_text(cls, label: str) -> "SourceIdentity":
        return cls(
            display_label=label,
            location=TextLocation(label=label, line=1)
        )

    @classmethod
    def for_http_response(
        cls,
        requested_url: str,
        effective_url: str
    ) -> "SourceIdentity":
        return cls(
            display_label=effective_url,
            location=HttpLocation(
                requested_url=requested_url,
                effective_url=effective_url,
                line=1
            )
        )


@dataclass(frozen=True)
class SourcePathResolver:
    base_path: Path | None = None

    @classmethod
    def for_target(cls, target: str | Path) -> "SourcePathResolver":
        target_path = Path(target).resolve()
        base_path = (
            target_path
            if target_path.is_dir()
            else target_path.parent
        )
        return cls(base_path)

    def identify_resolved_file(self, path: Path) -> SourceIdentity:
        if not path.is_absolute():
            raise ValueError("Resolved source path must be absolute")

        return SourceIdentity(
            display_label=str(path),
            location=FileLocation(
                path=self._location_path(path),
                line=1
            )
        )

    def identify_git_blob(
        self,
        display_path: str | Path,
        commit_sha: str
    ) -> SourceIdentity:
        display_label = str(display_path)
        path = Path(display_path)
        if not path.is_absolute():
            path = Path.cwd() / path

        return SourceIdentity(
            display_label=display_label,
            location=GitLocation(
                path=self._location_path(path.resolve()),
                commit_sha=commit_sha,
                line=1
            )
        )

    def _location_path(self, path: Path) -> str:
        return (
            str(path.relative_to(self.base_path))
            if self.base_path
            and path.is_relative_to(self.base_path)
            else str(path)
        )
