from dataclasses import dataclass


HEX_ENTROPY_MAX = 4.5
B64_ENTROPY_MAX = 6.0
MAX_WORKERS_MULTIPLIER = 2


@dataclass(frozen=True)
class ScanOptions:
    hex_entropy_threshold: float = 3.0
    b64_entropy_threshold: float = 4.25
    min_string_length: int = 10
    max_workers: int = 4
    max_source_bytes: int = 10 * 1024 * 1024
    source_timeout_seconds: float = 5.0


@dataclass(frozen=True)
class FindingOutputOptions:
    min_confidence: int = 0
    reveal_findings: bool = False
    truncate_long_matches: bool = False


DEFAULT_SCAN_OPTIONS = ScanOptions()
DEFAULT_FINDING_OUTPUT_OPTIONS = FindingOutputOptions()
