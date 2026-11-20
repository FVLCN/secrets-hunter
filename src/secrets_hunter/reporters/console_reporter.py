from secrets_hunter.models import GitLocation, HttpLocation
from secrets_hunter.reporters.console_base import BaseConsoleReporter
from secrets_hunter.reporters.finding_view import FindingView


class ConsoleReporter(BaseConsoleReporter):
    @staticmethod
    def _truncate(s: str | None, max_len: int) -> str:
        if not s:
            return ""
        s = s.replace("\n", "\\n")
        return s if len(s) <= max_len else s[: max_len - 3] + "..."

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

                matched = semantic_analysis.matched_signals
                if matched:
                    lines.append("    Matched:")
                    lines.extend(f"      {signal.text}" for signal in matched)

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
