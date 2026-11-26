from pathlib import Path


def validate_path_target(target: str | Path) -> None:
    if not isinstance(target, (str, Path)):
        raise TypeError("target must be a string or Path")

    if isinstance(target, str) and not target.strip():
        raise ValueError("target must not be empty")
