from secrets_hunter.models import GitLocation, HttpLocation
from secrets_hunter.reporters.console_base import BaseConsoleReporter
from secrets_hunter.reporters.finding_view import FindingView
from secrets_hunter.reporters.semantic_analysis_view import (
    SemanticConceptView,
    SemanticKeywordView,
)


class ConsoleReporter(BaseConsoleReporter):
    @staticmethod
    def _truncate(s: str | None, max_len: int) -> str:
        if not s:
            return ""
        s = s.replace("\n", "\\n")
        return s if len(s) <= max_len else s[: max_len - 3] + "..."

    @staticmethod
    def _format_keyword(keyword: SemanticKeywordView) -> str:
        return keyword.display_term or keyword.term

    @staticmethod
    def _format_concept(concept: SemanticConceptView) -> str:
        display_name = concept.display_name
        probability_percent = round(concept.probability * 100)

        keywords = [
            formatted
            for keyword in concept.strongest_keywords
            for formatted in [ConsoleReporter._format_keyword(keyword)]
            if formatted
        ]
        keyword_suffix = f" [{', '.join(keywords)}]" if keywords else ""

        return f"{display_name} {probability_percent}%{keyword_suffix}"

    @staticmethod
    def format_report(findings: list[FindingView]) -> None:
        if not findings:
            return

        sep = "=" * ConsoleReporter.WIDTH
        dash = "-" * ConsoleReporter.WIDTH

        lines: list[str] = [f"\n{sep}"]

        for i, f in enumerate(findings, 1):
            lines.append(f"[{i}] {f.title}")
            severity_detail = f"Confidence: {f.confidence}%"

            if f.confidence_reasoning:
                severity_detail += f", {f.confidence_reasoning}"

            lines.append(f"    Severity:   {f.severity} ({severity_detail})")

            semantic_analysis = f.semantic_analysis

            if semantic_analysis:
                facts = semantic_analysis.facts
                signals = [
                    ConsoleReporter._format_concept(concept)
                    for concept in semantic_analysis.concepts
                ]

                if facts:
                    lines.append(f"    Facts:      {', '.join(facts)}")

                if signals:
                    lines.append(f"    Signals:    {', '.join(signals)}")

            shadowed_rules = f.shadowed_rule_ids
            decision_summary = f.selected_rule_id

            if shadowed_rules:
                decision_summary += f" (shadowed: {', '.join(shadowed_rules)})"

            lines.append(f"    Decision:   {decision_summary}")

            location = f.location
            if isinstance(location, GitLocation):
                lines.append(f"    Commit:     {location.commit_sha}")

            if isinstance(location, HttpLocation):
                lines.append(f"    URL:        {location.effective_url}")
                if location.requested_url != location.effective_url:
                    lines.append(
                        f"    Requested:  {location.requested_url}"
                    )

            if f.associated_name:
                lines.append(f"    Associated name: {f.associated_name}")

            match_str = ConsoleReporter._truncate(f.match, 120)
            if match_str:
                lines.append(f"    Match:      {match_str}")

            ctx_str = ConsoleReporter._truncate(f.context, 160)
            if ctx_str:
                lines.append(f"    Context:    {ctx_str}")

            lines.append(dash)

        print("\n".join(lines))
