from secrets_hunter.detection.detectors.models import (
    DetectionCandidate,
    DetectionPattern
)
from secrets_hunter.detection.fragmenter import LineFragment
from secrets_hunter.detection.pattern_plan import PatternDetectionPlan
from secrets_hunter.models import DetectionMethod, FindingKind


class PatternDetector:
    """Detects secrets using regex patterns"""

    def __init__(
        self,
        plan: PatternDetectionPlan
    ) -> None:
        self.plan = plan

    def _create_candidate(
        self,
        finding_kind: FindingKind,
        fragment: LineFragment,
        line: str,
        line_num: int,
        filepath: str,
        pattern: DetectionPattern | None = None
    ) -> DetectionCandidate:
        return DetectionCandidate(
            file=filepath,
            line=line_num,
            finding_kind=finding_kind,
            match=fragment.content,
            context=line.strip()[:100],
            detection_method=DetectionMethod.PATTERN,
            fragment=fragment,
            provider_pattern_id=pattern.provider_pattern_id if pattern else None
        )

    def detect(
        self,
        line: str,
        line_num: int,
        filepath: str,
        fragments: list[LineFragment]
    ) -> list[DetectionCandidate]:
        candidates: list[DetectionCandidate] = []

        for fragment in fragments:
            if fragment.special_finding_kind:
                candidate = self._create_candidate(
                    fragment.special_finding_kind,
                    fragment,
                    line,
                    line_num,
                    filepath
                )
                candidates.append(candidate)
                continue

            if (
                self.plan.prefilter is not None
                and not self.plan.prefilter.search(fragment.content)
            ):
                continue

            for pattern in self.plan.patterns:
                if pattern.search(fragment.content):
                    candidate = self._create_candidate(
                        pattern.kind,
                        fragment,
                        line,
                        line_num,
                        filepath,
                        pattern
                    )
                    candidates.append(candidate)

        return candidates
