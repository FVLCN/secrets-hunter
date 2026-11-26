import re

from collections.abc import Iterable
from dataclasses import dataclass

from secrets_hunter.detection.detectors.models import DetectionPattern


@dataclass(frozen=True)
class PatternDetectionPlan:
    patterns: tuple[DetectionPattern, ...]
    prefilter: re.Pattern[str] | None


def build_pattern_detection_plan(
    patterns: Iterable[DetectionPattern]
) -> PatternDetectionPlan:
    ordered_patterns = tuple(patterns)
    return PatternDetectionPlan(
        patterns=ordered_patterns,
        prefilter=_compile_safe_prefilter(
            tuple(pattern.compiled for pattern in ordered_patterns)
        )
    )


def _compile_safe_prefilter(
    patterns: tuple[re.Pattern[str], ...]
) -> re.Pattern[str] | None:
    if not patterns:
        return None

    if any(pattern.groups for pattern in patterns):
        return None

    if any(pattern.flags != re.UNICODE for pattern in patterns):
        return None

    combined_pattern = "|".join(
        f"(?:{pattern.pattern})"
        for pattern in patterns
    )

    try:
        return re.compile(combined_pattern)
    except re.error:
        return None
