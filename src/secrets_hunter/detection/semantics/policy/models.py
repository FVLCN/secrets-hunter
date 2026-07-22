from dataclasses import dataclass

from secrets_hunter.detection.semantics.catalog import ConceptId, Provider
from secrets_hunter.detection.semantics.evidence_sources import EvidenceSource
from secrets_hunter.models import Decision, SemanticAnalysisResult


@dataclass(frozen=True)
class ConceptKeywordEvidence:
    term: str
    source: EvidenceSource
    display_term: str | None = None
    provider: Provider | None = None


@dataclass(frozen=True)
class ProviderMatch:
    provider: Provider
    strongest_keywords: tuple[ConceptKeywordEvidence, ...]
    matched_pattern_id: str | None = None

    @property
    def id(self) -> str:
        return self.provider.id

    @property
    def name(self) -> str:
        return self.provider.name

    @property
    def kind(self) -> str:
        return self.provider.kind

    @property
    def target_concept(self) -> ConceptId:
        return self.provider.target_concept


@dataclass(frozen=True)
class ConceptProbability:
    name: ConceptId
    probability: float
    strongest_keywords: tuple[ConceptKeywordEvidence, ...]
    kind: str = "signal"
    display_name: str | None = None


@dataclass(frozen=True)
class ConceptPolicyResult:
    analysis: SemanticAnalysisResult
    decision: Decision
