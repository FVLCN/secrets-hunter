from dataclasses import dataclass

from .fact import Fact


@dataclass(frozen=True)
class SemanticKeywordEvidenceResult:
    term: str
    source: str
    strength: str = "strong"
    display_term: str | None = None
    provider_id: str | None = None
    provider_name: str | None = None
    provider_kind: str | None = None


@dataclass(frozen=True)
class SemanticConceptResult:
    concept_id: str
    probability: float | None
    strongest_keywords: tuple[SemanticKeywordEvidenceResult, ...]
    origin: str
    strength: str
    display_name: str | None = None


@dataclass(frozen=True)
class SemanticProviderMatchResult:
    id: str
    name: str
    kind: str
    target_concept_id: str
    strongest_keywords: tuple[SemanticKeywordEvidenceResult, ...]
    matched_pattern_id: str | None = None


@dataclass(frozen=True)
class SemanticAnalysisResult:
    concepts: tuple[SemanticConceptResult, ...]
    providers: tuple[SemanticProviderMatchResult, ...]
    facts: tuple[Fact, ...]

    @property
    def pattern_provider_match(self) -> SemanticProviderMatchResult | None:
        return next(
            (
                provider
                for provider in self.providers
                if provider.matched_pattern_id is not None
            ),
            None,
        )
