from dataclasses import dataclass
from typing import Self

from secrets_hunter.models import (
    DetectionMethod,
    Disposition,
    Finding,
    FindingKind,
    Severity,
)
from secrets_hunter.reporters.rule_activation_view import RuleActivationView
from secrets_hunter.reporters.semantic_analysis_view import SemanticAnalysisView


@dataclass(frozen=True)
class FindingView:
    title: str
    file: str
    line: int
    kind: FindingKind
    match: str
    context: str
    detection_method: DetectionMethod
    severity: Severity
    confidence: int
    confidence_reasoning: str
    disposition: Disposition
    decision_trace: tuple[RuleActivationView, ...]
    context_var: str | None = None
    commit: str | None = None
    vulnerable_url: str | None = None
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
            finding.context_var.replace("_", " ")
            if finding.context_var
            else finding.kind.display_name
        )
        return cls(
            title=f"Hardcoded {title_subject} at {finding.file}:{finding.line}",
            file=finding.file,
            line=finding.line,
            kind=finding.kind,
            match=match,
            context=context,
            detection_method=finding.detection_method,
            severity=finding.severity,
            confidence=finding.confidence,
            confidence_reasoning=finding.confidence_reasoning,
            disposition=finding.disposition,
            decision_trace=tuple(
                RuleActivationView.from_activation(activation)
                for activation in finding.decision_trace
            ),
            context_var=finding.context_var,
            commit=finding.commit,
            vulnerable_url=finding.vulnerable_url,
            semantic_analysis=(
                SemanticAnalysisView.from_result(finding.semantic_analysis)
                if finding.semantic_analysis is not None
                else None
            ),
        )

    @property
    def selected_rule_id(self) -> str:
        return next(
            activation.rule_id
            for activation in self.decision_trace
            if activation.selected
        )

    @property
    def shadowed_rule_ids(self) -> tuple[str, ...]:
        return tuple(
            activation.rule_id
            for activation in self.decision_trace
            if not activation.selected
        )

    def to_dict(self) -> dict[str, object]:
        data: dict[str, object] = {
            "title": self.title,
            "file": self.file,
            "line": self.line,
            "finding_kind": {
                "id": self.kind.id,
                "display_name": self.kind.display_name
            },
            "match": self.match,
            "context": self.context,
            "detection_method": self.detection_method,
            "context_var": self.context_var,
            "commit": self.commit,
            "vulnerable_url": self.vulnerable_url,
            "severity": self.severity,
            "confidence_reasoning": self.confidence_reasoning,
            "confidence": self.confidence,
            "disposition": self.disposition.value,
            "decision_trace": [
                activation.to_dict()
                for activation in self.decision_trace
            ]
        }

        if self.semantic_analysis is not None:
            data["semantic_analysis"] = self.semantic_analysis.to_dict()
            pattern_provider = self.semantic_analysis.pattern_provider_match

            if pattern_provider is not None:
                data["provider_pattern_id"] = pattern_provider.matched_pattern_id
                data["provider_id"] = pattern_provider.id
                data["provider_name"] = pattern_provider.name
                data["provider_kind"] = pattern_provider.kind

        return data
