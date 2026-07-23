from pathlib import Path


class PathFilter:
    def __init__(
        self,
        ignore_files: set[str],
        ignore_extensions: set[str],
        ignore_dirs: set[str]
    ) -> None:
        self.ignore_files = ignore_files
        self.ignore_extensions = {ext.lower() for ext in ignore_extensions}
        self.ignore_dirs = ignore_dirs

    def is_ignored_path(self, path: Path) -> bool:
        if path.name in self.ignore_files:
            return True

        if path.suffix.lower() in self.ignore_extensions:
            return True

        return any(part in self.ignore_dirs for part in path.parts[:-1])

    def is_ignored_directory(self, path: Path) -> bool:
        return any(part in self.ignore_dirs for part in path.parts)
