from secrets_hunter.detection.assignment_resolver import AssignmentResolver
from secrets_hunter.detection.candidate_assessor import CandidateAssessor
from secrets_hunter.detection.detectors.base import Detector
from secrets_hunter.detection.detectors.models import DetectionCandidate
from secrets_hunter.detection.fragmenter.fragmenter import SourceFragmenter
from secrets_hunter.detection.fragmenter.models import LineFragment, SourceFragment
from secrets_hunter.models import Finding, SourceLocation


class DetectionEngine:
    def __init__(
        self,
        pattern_detector: Detector,
        entropy_detector: Detector,
        source_fragmenter: SourceFragmenter,
        assignment_resolver: AssignmentResolver,
        candidate_assessor: CandidateAssessor
    ) -> None:
        self.pattern_detector = pattern_detector
        self.entropy_detector = entropy_detector
        self.source_fragmenter = source_fragmenter
        self.assignment_resolver = assignment_resolver
        self.candidate_assessor = candidate_assessor

    def _detect_candidates(
        self,
        fragments: list[LineFragment],
        source: str,
        line: int,
        source_location: SourceLocation
    ) -> list[DetectionCandidate]:
        entropy_candidates = self.entropy_detector.detect(
            source,
            line,
            source_location,
            fragments
        )
        pattern_candidates = self.pattern_detector.detect(
            source,
            line,
            source_location,
            fragments
        )
        pattern_matches = {
            candidate.match
            for candidate in pattern_candidates
        }

        return [
            *pattern_candidates,
            *(
                candidate
                for candidate in entropy_candidates
                if candidate.match not in pattern_matches
            )
        ]

    def scan_fragment(
        self,
        source_fragment: SourceFragment,
        source_location: SourceLocation
    ) -> list[Finding]:
        fragments = self.source_fragmenter.extract(source_fragment)

        if not fragments:
            return []

        candidates = self._detect_candidates(
            fragments,
            source_fragment.content,
            source_fragment.start_line,
            source_location
        )

        if not candidates:
            return []

        assignment_context = self.assignment_resolver.build(
            source_fragment.content
        )
        return [
            self.candidate_assessor.assess(
                candidate,
                assignment_context.associated_names_for(
                    match=candidate.match,
                    candidate_context=candidate.context
                )
            )
            for candidate in candidates
        ]
