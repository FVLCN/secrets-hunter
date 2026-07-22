from dataclasses import dataclass


@dataclass(frozen=True)
class SemanticKeywordEvidenceResult:
    term: str
    source: str
    display_term: str | None = None
    provider_id: str | None = None
    provider_name: str | None = None
    provider_kind: str | None = None


@dataclass(frozen=True)
class SemanticConceptResult:
    name: str
    probability: float
    strongest_keywords: tuple[SemanticKeywordEvidenceResult, ...]
    kind: str = "signal"
    display_name: str | None = None


@dataclass(frozen=True)
class SemanticProviderMatchResult:
    id: str
    name: str
    kind: str
    target_concept: str
    strongest_keywords: tuple[SemanticKeywordEvidenceResult, ...]
    matched_pattern_id: str | None = None


@dataclass(frozen=True)
class SemanticAnalysisResult:
    concepts: tuple[SemanticConceptResult, ...]
    providers: tuple[SemanticProviderMatchResult, ...]
    facts: tuple[str, ...]

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
