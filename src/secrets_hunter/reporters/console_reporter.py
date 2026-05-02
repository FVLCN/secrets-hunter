from typing import Optional

from secrets_hunter.reporters.console_base import BaseConsoleReporter
from secrets_hunter.models import Finding


class ConsoleReporter(BaseConsoleReporter):
    @staticmethod
    def _truncate(s: Optional[str], max_len: int) -> str:
        if not s:
            return ""
        s = s.replace("\n", "\\n")
        return s if len(s) <= max_len else s[: max_len - 3] + "..."

    @staticmethod
    def format_report(findings: list[Finding]) -> None:
        if not findings:
            return

        sep = "=" * ConsoleReporter.WIDTH
        dash = "-" * ConsoleReporter.WIDTH

        lines: list[str] = [f"\n{sep}"]

        for i, f in enumerate(findings, 1):
            lines.append(f"[{i}] {f.title}")
            lines.append(f"    Severity:   {f.severity} (confidence: {f.confidence}%, reasoning: {f.confidence_reasoning})")

            if getattr(f, "context_var", None):
                lines.append(f"    Variable:   {f.context_var}")

            match_str = ConsoleReporter._truncate(f.match, 120)
            if match_str:
                lines.append(f"    Match:      {match_str}")

            ctx_str = ConsoleReporter._truncate(f.context, 160)
            if ctx_str:
                lines.append(f"    Context:    {ctx_str}")

            lines.append(dash)

        print("\n".join(lines))
