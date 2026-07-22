from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


@dataclass(frozen=True)
class SourceIdentity:
    display_label: str
    finding_path: str


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

    def identify(self, display_path: str | Path) -> SourceIdentity:
        display_label = str(display_path)
        parsed = urlparse(display_label)

        if parsed.scheme in {"http", "https"}:
            return SourceIdentity(display_label, display_label)

        path = Path(display_label)
        if not path.is_absolute():
            path = Path.cwd() / path

        return self._identify_resolved(
            path.resolve(),
            display_label
        )

    def identify_resolved(self, path: Path) -> SourceIdentity:
        if not path.is_absolute():
            raise ValueError("Resolved source path must be absolute")

        return self._identify_resolved(path, str(path))

    def _identify_resolved(
        self,
        path: Path,
        display_label: str
    ) -> SourceIdentity:
        finding_path = (
            str(path.relative_to(self.base_path))
            if self.base_path
            and path.is_relative_to(self.base_path)
            else str(path)
        )
        return SourceIdentity(display_label, finding_path)
