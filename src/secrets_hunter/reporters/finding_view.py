from dataclasses import dataclass
from typing import Self

from secrets_hunter.models import (
    Decision,
    DetectionMethod,
    Disposition,
    Finding,
    FindingKind,
    Severity,
    SourceLocation,
    severity_for_confidence,
)
from secrets_hunter.reporters.semantic_analysis_view import SemanticAnalysisView
from secrets_hunter.reporters.source_location import (
    format_source_location,
    source_location_to_dict
)


@dataclass(frozen=True)
class FindingView:
    title: str
    location: SourceLocation
    kind: FindingKind
    match: str
    context: str
    detection_method: DetectionMethod
    decision: Decision
    associated_name: str | None = None
    semantic_analysis: SemanticAnalysisView | None = None

    @classmethod
    def from_finding(
        cls,
        finding: Finding,
        *,
        match: str,
        context: str
    ) -> Self:
        title_subject = (
            finding.associated_name.replace("_", " ")
            if finding.associated_name
            else finding.kind.display_name
        )
        return cls(
            title=(
                f"Hardcoded {title_subject} at "
                f"{format_source_location(finding.location)}"
            ),
            location=finding.location,
            kind=finding.kind,
            match=match,
            context=context,
            detection_method=finding.detection_method,
            decision=finding.decision,
            associated_name=finding.associated_name,
            semantic_analysis=(
                SemanticAnalysisView.from_result(finding.semantic_analysis)
                if finding.semantic_analysis is not None
                else None
            )
        )

    @property
    def confidence(self) -> int:
        return round(self.decision.confidence * 100)

    @property
    def confidence_reasoning(self) -> str:
        return self.decision.reasoning

    @property
    def disposition(self) -> Disposition:
        return self.decision.disposition

    @property
    def severity(self) -> Severity:
        return severity_for_confidence(self.confidence)

    @property
    def selected_rule_id(self) -> str:
        return self.decision.selected_rule.rule_id

    @property
    def decision_text(self) -> str:
        summary = self.disposition.value.capitalize()
        if self.selected_rule_id == "strong_fixture_confidence_cap":
            return f"{summary} — strong fixture evidence"
        if self.confidence_reasoning:
            return f"{summary} — {self.confidence_reasoning}"
        return summary

    def decision_to_dict(self) -> dict[str, object]:
        selected = self.decision.selected_rule
        reasoning = selected.reasoning
        return {
            "rule_id": selected.rule_id,
            "phase": selected.phase,
            "disposition": selected.disposition.value,
            "confidence": self.confidence,
            "reasoning": reasoning[:1].upper() + reasoning[1:],
        }

    def to_dict(self) -> dict[str, object]:
        data: dict[str, object] = {
            "title": self.title,
            "location": source_location_to_dict(self.location),
            "finding_kind": {
                "id": self.kind.id,
                "display_name": self.kind.display_name
            },
            "match": self.match,
            "context": self.context,
            "detection_method": self.detection_method,
            "associated_name": self.associated_name,
            "severity": self.severity,
            "decision": self.decision_to_dict(),
        }

        if self.semantic_analysis is not None:
            data["semantic_analysis"] = self.semantic_analysis.to_dict()

        return data
