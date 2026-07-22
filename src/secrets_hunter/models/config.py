import re

from dataclasses import dataclass

from .rejection import RejectionPattern


@dataclass(frozen=True)
class RuntimeConfig:
    rejection_patterns: tuple[RejectionPattern, ...]
    compiled_assignment_patterns: tuple[re.Pattern[str], ...]
    ignore_files: tuple[str, ...]
    ignore_extensions: tuple[str, ...]
    ignore_dirs: tuple[str, ...]
