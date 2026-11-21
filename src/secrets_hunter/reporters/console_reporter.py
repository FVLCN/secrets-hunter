from secrets_hunter.models import GitLocation, HttpLocation
from secrets_hunter.reporters.console_base import BaseConsoleReporter
from secrets_hunter.reporters.finding_view import FindingView
from secrets_hunter.reporters.semantic_analysis_view import SemanticConceptView


class ConsoleReporter(BaseConsoleReporter):
    @staticmethod
    def _truncate(s: str | None, max_len: int) -> str:
        if not s:
            return ""
        s = s.replace("\n", "\\n")
        return s if len(s) <= max_len else s[: max_len - 3] + "..."

    @staticmethod
    def _format_matched_concept(concept: SemanticConceptView) -> list[str]:
        terms_by_source: dict[str, list[str]] = {}
        providers: list[tuple[str, str]] = []
        for evidence in concept.evidence:
            term = evidence.term
            if not term:
                continue

            source = (
                "name"
                if evidence.source == "var_name"
                else evidence.source.replace("_", " ")
            )
            terms = terms_by_source.setdefault(source, [])
            if term not in terms:
                terms.append(term)

            if evidence.provider_id is not None:
                provider = (
                    evidence.provider_id,
                    evidence.provider_name or evidence.provider_id,
                )
                if provider not in providers:
                    providers.append(provider)

        details: list[tuple[str, str]] = []
        if providers:
            label = "Provider" if len(providers) == 1 else "Providers"
            details.append((label, ", ".join(name for _, name in providers)))
        details.extend(
            (source.capitalize(), ", ".join(terms))
            for source, terms in terms_by_source.items()
            if terms
        )

        label_width = max((len(label) for label, _ in details), default=0)
        lines = [f"      {concept.concept_id} [{concept.strength}]"]
        lines.extend(
            f"          {(label + ':').ljust(label_width + 1)} {value}"
            for label, value in details
        )
        return lines

    @staticmethod
    def format_report(findings: list[FindingView]) -> None:
        if not findings:
            return

        sep = "=" * ConsoleReporter.WIDTH
        dash = "-" * ConsoleReporter.WIDTH

        lines: list[str] = [f"\n{sep}"]

        for i, f in enumerate(findings, 1):
            lines.append(f"[{i}] {f.title}")
            match_str = ConsoleReporter._truncate(f.match, 120)
            if match_str:
                lines.append(f"    Value:      {match_str}")

            lines.append(f"    Confidence: {f.confidence}% [{f.severity}]")

            if f.associated_name:
                lines.append(f"    Name:       {f.associated_name}")

            ctx_str = ConsoleReporter._truncate(f.context, 160)
            if ctx_str:
                lines.append(f"    Context:    {ctx_str}")

            lines.append(f"    Decision:   {f.decision_text}")

            semantic_analysis = f.semantic_analysis

            if semantic_analysis:
                facts = [fact.text for fact in semantic_analysis.facts]
                if facts:
                    lines.append(f"    Facts:      {', '.join(facts)}")

                matched = tuple(
                    concept
                    for concept in semantic_analysis.concepts
                    if concept.origin == "evidence"
                )
                if matched:
                    lines.append("    Matched:")
                    for concept in matched:
                        lines.extend(
                            ConsoleReporter._format_matched_concept(concept)
                        )

                inferred = semantic_analysis.inferred_signals
                if inferred:
                    lines.append("    Inferred:")
                    lines.extend(
                        f"      {signal.text}"
                        for signal in inferred
                    )

            location = f.location
            if isinstance(location, GitLocation):
                lines.append(f"    Commit:     {location.commit_sha}")

            if isinstance(location, HttpLocation):
                lines.append(f"    URL:        {location.effective_url}")
                if location.requested_url != location.effective_url:
                    lines.append(
                        f"    Requested:  {location.requested_url}"
                    )

            lines.append(dash)

        print("\n".join(lines))
