from dataclasses import dataclass
from enum import StrEnum

from .decision import Decision, Disposition, RuleActivation
from .finding_kind import FindingKind
from .semantic_analysis import SemanticAnalysisResult
from .source_location import SourceLocation


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"

    def __str__(self) -> str:
        return self.name


def severity_for_confidence(confidence: int) -> Severity:
    confidence = int(confidence)

    if confidence < 0 or confidence > 100:
        raise ValueError(f"confidence must be between 0 and 100, got {confidence}")

    if confidence <= 10:
        return Severity.INFO

    if confidence <= 35:
        return Severity.LOW

    if confidence <= 69:
        return Severity.MEDIUM

    if confidence <= 89:
        return Severity.HIGH

    return Severity.CRITICAL


class DetectionMethod(StrEnum):
    PATTERN = "pattern"
    ENTROPY = "entropy"


@dataclass(frozen=True)
class Finding:
    location: SourceLocation
    kind: FindingKind
    match: str
    context: str
    detection_method: DetectionMethod
    decision: Decision
    context_var: str | None = None
    semantic_analysis: SemanticAnalysisResult | None = None

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
    def decision_trace(self) -> tuple[RuleActivation, ...]:
        return self.decision.trace

    @property
    def severity(self) -> Severity:
        return severity_for_confidence(self.confidence)
