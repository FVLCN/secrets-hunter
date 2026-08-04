from secrets_hunter.detection.detectors.models import DetectionCandidate
from secrets_hunter.detection.fragmenter.models import PEMKeyFragment
from secrets_hunter.detection.rejection_analyzer import CandidateRejectionAnalyzer
from secrets_hunter.detection.semantics import ConceptPolicyResult, SemanticRuntime
from secrets_hunter.detection.semantics.observation import SemanticInput
from secrets_hunter.detection.value_analysis import (
    ValueAnalysis,
    ValueAnalyzer
)
from secrets_hunter.models import Finding, RejectionReason


class CandidateAssessor:
    def __init__(
        self,
        rejection_analyzer: CandidateRejectionAnalyzer,
        semantic_runtime: SemanticRuntime,
        value_analyzer: ValueAnalyzer
    ) -> None:
        self.rejection_analyzer = rejection_analyzer
        self.semantic_runtime = semantic_runtime
        self.value_analyzer = value_analyzer

    def _semantic_result(
        self,
        candidate: DetectionCandidate,
        associated_name: str | None,
        *,
        lexical_subject: str,
        rejection: RejectionReason | None,
        value_analysis: ValueAnalysis
    ) -> ConceptPolicyResult:
        item = SemanticInput(
            associated_name=associated_name or "",
            detection_method=candidate.detection_method,
            finding_kind=candidate.finding_kind,
            file_path=candidate.location.locator,
            value_analysis=value_analysis,
            lexical_subject=lexical_subject,
            pem_analysis=(
                candidate.fragment.pem_analysis
                if isinstance(candidate.fragment, PEMKeyFragment)
                else None
            ),
            value_rejection=rejection,
            provider_pattern_id=candidate.provider_pattern_id
        )
        return self.semantic_runtime.analyze(item)

    def _best_associated_name_result(
        self,
        candidate: DetectionCandidate,
        associated_names: tuple[str, ...],
        *,
        lexical_subject: str,
        rejection: RejectionReason | None,
        value_analysis: ValueAnalysis
    ) -> tuple[str | None, ConceptPolicyResult]:
        names = sorted(associated_names)

        if not names:
            return None, self._semantic_result(
                candidate,
                None,
                lexical_subject=lexical_subject,
                rejection=rejection,
                value_analysis=value_analysis
            )

        associated_name_results = [
            (
                name,
                self._semantic_result(
                    candidate,
                    name,
                    lexical_subject=lexical_subject,
                    rejection=rejection,
                    value_analysis=value_analysis
                )
            )
            for name in names
        ]

        return max(
            associated_name_results,
            key=lambda result: (
                result[1].decision.confidence,
                result[0]
            )
        )

    def assess(
        self,
        candidate: DetectionCandidate,
        associated_names: tuple[str, ...]
    ) -> Finding:
        lexical_subject = self.rejection_analyzer.lexical_subject_for_candidate(
            candidate
        )
        value_analysis = self.value_analyzer.analyze(
            candidate.match,
            candidate.entropy_classification
        )
        rejection = self.rejection_analyzer.rejection_for_candidate(
            candidate,
            lexical_subject,
            value_analysis.hash_classification
        )
        associated_name, semantic_result = self._best_associated_name_result(
            candidate,
            associated_names,
            lexical_subject=lexical_subject,
            rejection=rejection,
            value_analysis=value_analysis
        )

        return Finding(
            location=candidate.location,
            kind=candidate.finding_kind,
            match=candidate.match,
            context=candidate.context,
            detection_method=candidate.detection_method,
            decision=semantic_result.decision,
            associated_name=associated_name,
            semantic_analysis=semantic_result.analysis
        )
