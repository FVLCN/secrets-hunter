from dataclasses import dataclass

from secrets_hunter.detection.semantics.catalog import ConceptId, EvidenceStrength, Provider
from secrets_hunter.detection.semantics.evidence_sources import EvidenceSource
from secrets_hunter.models import Decision, SemanticAnalysisResult


@dataclass(frozen=True)
class ConceptKeywordEvidence:
    term: str
    source: EvidenceSource
    strength: EvidenceStrength = EvidenceStrength.STRONG
    display_term: str | None = None
    provider: Provider | None = None


@dataclass(frozen=True)
class ProviderMatch:
    provider: Provider
    strongest_keywords: tuple[ConceptKeywordEvidence, ...]
    matched_pattern_id: str | None = None
    public: bool = False

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
    def target_concept_id(self) -> ConceptId:
        return self.provider.target_concept_id


@dataclass(frozen=True)
class ResolvedConcept:
    concept_id: ConceptId
    origin: str
    strength: EvidenceStrength
    strongest_keywords: tuple[ConceptKeywordEvidence, ...]
    probability: float | None = None


@dataclass(frozen=True)
class ConceptPolicyResult:
    analysis: SemanticAnalysisResult
    decision: Decision
