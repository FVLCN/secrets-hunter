import re

from dataclasses import dataclass

from secrets_hunter.detection.entropy_classification import EntropyClassification
from secrets_hunter.detection.fragmenter.models import LineFragment
from secrets_hunter.models import DetectionMethod, FindingKind


@dataclass(frozen=True)
class DetectionCandidate:
    file: str
    line: int
    finding_kind: FindingKind
    match: str
    context: str
    detection_method: DetectionMethod
    fragment: LineFragment
    provider_pattern_id: str | None = None
    entropy_classification: EntropyClassification | None = None


@dataclass(frozen=True)
class DetectionPattern:
    kind: FindingKind
    compiled: re.Pattern[str]
    provider_pattern_id: str | None = None

    def search(self, text: str) -> re.Match[str] | None:
        return self.compiled.search(text)
