from secrets_hunter.detection.semantics.catalog import SemanticCatalog
from secrets_hunter.detection.semantics.classification import ConceptScores
from secrets_hunter.detection.semantics.observation.models import SemanticObservation

from .concept_groups import PolicyConceptGroups
from .decision import SecretDecisionPolicy
from .evidence import EvidenceCollector
from .indexes import PolicyIndexes
from .models import ConceptPolicyResult
from .presentation import PolicyPresentation
from .providers import ProviderMatcher
from .result_builder import build_semantic_analysis_result


class ConceptSecretPolicy:
    def __init__(
        self,
        catalog: SemanticCatalog,
        *,
        report_probability_threshold: float | None = None,
        report_limit: int | None = None
    ) -> None:
        self.catalog = catalog
        self.policy = catalog.policy
        self.report_probability_threshold = (
            self.policy.reporting.concept_probability_threshold
            if report_probability_threshold is None
            else report_probability_threshold
        )
        self.report_limit = (
            self.policy.reporting.concept_limit
            if report_limit is None
            else report_limit
        )
        self.indexes = PolicyIndexes.from_catalog(catalog)
        self.evidence = EvidenceCollector(catalog)
        self.providers = ProviderMatcher(catalog)
        self.decision = SecretDecisionPolicy(catalog)
        self.presentation = PolicyPresentation(
            catalog,
            self.indexes,
            report_probability_threshold=self.report_probability_threshold,
            report_limit=self.report_limit,
        )

    def evaluate(
        self,
        observation: SemanticObservation,
        concept_scores: ConceptScores,
    ) -> ConceptPolicyResult:
        tokens_by_source = observation.evidence_tokens_by_source()
        provider_matches = self.providers.matches(tokens_by_source, observation)
        evidence_by_concept = self.evidence.collect(
            tokens_by_source,
            observation,
            provider_matches=provider_matches
        )
        groups = PolicyConceptGroups.classify(
            concept_scores,
            self.indexes,
            self.policy,
        )
        decision = self.decision.decide(
            observation,
            groups,
            evidence_by_concept
        )

        return ConceptPolicyResult(
            analysis=build_semantic_analysis_result(
                concepts=self.presentation.reported_concepts(groups, evidence_by_concept),
                providers=provider_matches,
                facts=tuple(sorted(observation.facts)),
            ),
            decision=decision,
        )
