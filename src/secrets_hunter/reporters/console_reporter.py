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
    def _format_concept(concept: SemanticConceptView, name_width: int = 0) -> str:
        display_name = concept.display_name.ljust(name_width)

        presentation = concept.presentation
        if presentation is None:
            return f"{display_name} [{concept.strength}]"

        return f"{display_name} {presentation['text']}"

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

            decision_summary = f.disposition.value.capitalize()
            if f.selected_rule_id == "strong_fixture_confidence_cap":
                decision_summary += " — strong fixture evidence"
            elif f.confidence_reasoning:
                decision_summary += f" — {f.confidence_reasoning}"

            lines.append(f"    Decision:   {decision_summary}")

            semantic_analysis = f.semantic_analysis

            if semantic_analysis:
                fact_details = semantic_analysis.fact_details
                facts: list[str] = []
                for fact in semantic_analysis.facts:
                    if fact == "known_pattern_match":
                        facts.append(f"{fact} ({f.kind.display_name})")
                    elif fact == "hash_shaped_value" and fact in fact_details:
                        algorithm = str(fact_details[fact]["algorithm"]).upper()
                        facts.append(f"{fact} ({algorithm} shape)")
                    elif fact == "high_entropy" and fact in fact_details:
                        entropy = float(fact_details[fact]["bits_per_character"])
                        facts.append(f"{fact} ({entropy:.2f} bits/char)")
                    else:
                        facts.append(fact)
                matched = [
                    concept
                    for concept in semantic_analysis.concepts
                    if concept.origin == "evidence"
                ]
                inferred = [
                    concept
                    for concept in semantic_analysis.concepts
                    if concept.origin == "model"
                ]

                if facts:
                    lines.append(f"    Facts:      {', '.join(facts)}")

                if matched:
                    lines.append("    Matched:")
                    for concept in matched:
                        lines.append(f"      {ConsoleReporter._format_concept(concept)}")
                        keyword_groups = concept.keyword_groups
                        providers = {
                            provider["id"]: provider["name"]
                            for group in keyword_groups
                            for provider in group["providers"]
                        }
                        details: list[tuple[str, str]] = []
                        if providers:
                            label = "Provider" if len(providers) == 1 else "Providers"
                            details.append((label, ", ".join(providers.values())))
                        details.extend(
                            (group["label"].capitalize(), ", ".join(group["terms"]))
                            for group in keyword_groups
                            if group["terms"]
                        )
                        label_width = max(
                            (len(label) for label, _ in details),
                            default=0,
                        )
                        lines.extend(
                            f"          {(label + ':').ljust(label_width + 1)} {value}"
                            for label, value in details
                        )

                if inferred:
                    lines.append("    Inferred:")
                    name_width = max(len(concept.display_name) for concept in inferred)
                    lines.extend(
                        f"      {ConsoleReporter._format_concept(concept, name_width)}"
                        for concept in inferred
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
