from typing import Protocol

from secrets_hunter.detection.fragmenter.models import LineFragment
from secrets_hunter.models import SourceLocation

from .models import DetectionCandidate


class Detector(Protocol):
    def detect(
        self,
        line: str,
        line_num: int,
        source_location: SourceLocation,
        fragments: list[LineFragment]
    ) -> list[DetectionCandidate]:
        ...
