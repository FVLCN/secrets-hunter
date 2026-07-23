from typing import Protocol

from secrets_hunter.detection.fragmenter.models import LineFragment

from .models import DetectionCandidate


class Detector(Protocol):
    def detect(
        self,
        line: str,
        line_num: int,
        filepath: str,
        fragments: list[LineFragment]
    ) -> list[DetectionCandidate]:
        ...
