from secrets_hunter.detection.entropy_classification import EntropyClassifier
from secrets_hunter.detection.fragmenter import LineFragment
from secrets_hunter.models import DetectionMethod, SourceLocation

from .models import DetectionCandidate


class EntropyDetector:
    """Detect secrets using entropy analysis"""

    def __init__(self, classifier: EntropyClassifier) -> None:
        self.classifier = classifier

    def detect(
        self,
        line: str,
        line_num: int,
        source_location: SourceLocation,
        fragments: list[LineFragment]
    ) -> list[DetectionCandidate]:
        candidates: list[DetectionCandidate] = []

        for fragment in fragments:
            classification = self.classifier.classify(fragment.content)

            if classification is None:
                continue

            candidates.append(DetectionCandidate(
                location=source_location.at_line(line_num),
                finding_kind=classification.finding_kind,
                match=fragment.content,
                context=line.strip()[:100],
                detection_method=DetectionMethod.ENTROPY,
                fragment=fragment,
                entropy_classification=classification
            ))

        return candidates
