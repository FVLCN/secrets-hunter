import json
from pathlib import Path
import sys
from typing import TextIO

from secrets_hunter.reporters.finding_view import FindingView

from benchmark.models import ExpectedDisposition, NoFinding
from benchmark.report import (
    BenchmarkObservation,
    BenchmarkReport,
)


MAX_SCANNED_LINE_CHARS = 50
MAX_CASE_ENTRY_CHARS = 32
MAX_FILE_PATH_CHARS = 28


class BenchmarkPresentation:
    @staticmethod
    def render_json_summary(
        report: BenchmarkReport,
        output_file: str | Path,
        stream: TextIO | None = None,
    ) -> None:
        output = stream or sys.stdout
        counts = [f"{report.entry_count - report.failing_expectations} passed"]
        failed = report.failing_expectations - report.known_problem_failures
        if failed:
            counts.append(f"{failed} failed")
        if report.known_problem_failures:
            count = report.known_problem_failures
            counts.append(f"{count} known problem{'s' if count != 1 else ''}")
        if report.unexpected_findings:
            count = report.unexpected_findings
            counts.append(f"{count} unexpected finding{'s' if count != 1 else ''}")
        print(
            f"Result: {'PASSED' if report.passed else 'FAILED'} — {', '.join(counts)}",
            file=output,
        )
        print(f"Report saved to: {output_file}", file=output)

    @staticmethod
    def render_console(report: BenchmarkReport, stream: TextIO | None = None) -> None:
        output = stream or sys.stdout
        headers = (
            "#",
            "CASE / ENTRY",
            "SCANNED LINE",
            "FILE",
            "EXPECTED",
            "SCORE",
            "MET?",
        )
        table_rows: list[tuple[str, ...]] = []

        for observation in report.observations:
            entry = observation.entry
            finding = observation.finding
            if entry is None:
                label = f"{observation.case.case_id}/unexpected"
                expected = "no_entry"
                score = "-" if finding is None else f"{finding.confidence}%"
                result = "✗"
            else:
                result = "✓" if observation.expectation_met else "✗"
                label = f"{observation.case.case_id}/{entry.id}"
                expected = BenchmarkPresentation._display_disposition(
                    entry.expected_disposition
                )
                score = "-" if finding is None else f"{finding.confidence}%"

            label = BenchmarkPresentation._truncate_middle(
                label, MAX_CASE_ENTRY_CHARS
            )
            if observation.known_problem and result == "✗":
                result = "✗*"

            table_rows.append(
                tuple(
                    BenchmarkPresentation._cell(value)
                    for value in (
                        label,
                        BenchmarkPresentation._truncate_scanned_line(
                            observation.source_line
                        ),
                        BenchmarkPresentation._truncate_middle(
                            observation.file_path, MAX_FILE_PATH_CHARS
                        ),
                        expected,
                        score,
                        result,
                    )
                )
            )

        table_rows.sort(
            key=lambda row: (
                row[5].startswith("✗"),
                -(
                    float(row[4].removesuffix("%"))
                    if row[4] != "-"
                    else float("-inf")
                ),
            )
        )
        numbered_rows = [
            (str(index), *row)
            for index, row in enumerate(table_rows, start=1)
        ]
        widths = [
            max(len(headers[index]), *(len(row[index]) for row in numbered_rows))
            for index in range(len(headers))
        ]

        def print_row(values: tuple[str, ...]) -> None:
            print(
                " | ".join(
                    value.ljust(widths[index])
                    for index, value in enumerate(values)
                ),
                file=output,
            )

        print_row(headers)
        print("-+-".join("-" * width for width in widths), file=output)
        for row in numbered_rows:
            print_row(row)
        if any(observation.known_problem for observation in report.observations):
            print(
                "\n* known problem; failure remains visible but does not fail the benchmark",
                file=output,
            )
        failed_observations = [
            observation
            for observation in report.observations
            if observation.fails_benchmark
        ]
        if failed_observations:
            print("\nErrors:", file=output)
            for observation in failed_observations:
                entry_id = (
                    observation.entry.id
                    if observation.entry is not None
                    else "unexpected"
                )
                print(
                    f"  {BenchmarkPresentation._cell(observation.case.case_id)}/"
                    f"{BenchmarkPresentation._cell(entry_id)} "
                    f"({BenchmarkPresentation._cell(observation.file_path)}:"
                    f"{observation.line})",
                    file=output,
                )
                for mismatch in observation.mismatches:
                    print(
                        f"    {mismatch.field}: expected {mismatch.expected!r}, "
                        f"actual {mismatch.actual!r}",
                        file=output,
                    )

    @staticmethod
    def build_json_report(report: BenchmarkReport) -> dict[str, object]:
        return {
            "schema_version": 1,
            "tool": report.tool.to_dict(),
            "generated_at": report.generated_at.isoformat(
                timespec="seconds"
            ).replace("+00:00", "Z"),
            "case_data_sha256": report.case_data_sha256,
            "benchmark": {
                "case_count": len(report.cases),
                "entry_count": report.entry_count,
                "passed": report.passed,
                "failing_expectations": report.failing_expectations,
                "known_problem_failures": report.known_problem_failures,
                "unexpected_findings": report.unexpected_findings,
            },
            "cases": [
                {
                    "case_id": case.case_id,
                    "case_path": case.case_path,
                    "description": case.description,
                    "category": case.category.value,
                }
                for case in report.cases
            ],
            "observations": [
                BenchmarkPresentation._observation_to_dict(item)
                for item in report.observations
            ],
        }

    @classmethod
    def write_json_report(
        cls, report: BenchmarkReport, output_file: str | Path
    ) -> None:
        with Path(output_file).open(
            "w", encoding="utf-8", errors="backslashreplace"
        ) as output:
            json.dump(
                cls.build_json_report(report), output, indent=4, ensure_ascii=False
            )
            output.write("\n")

    @staticmethod
    def _observation_to_dict(
        observation: BenchmarkObservation
    ) -> dict[str, object]:
        entry = observation.entry
        finding = observation.finding
        expected: dict[str, object] | None = None
        if entry is not None:
            expected = {
                "disposition": entry.expected_disposition.value,
                "confidence_min": entry.confidence_min,
                "confidence_max": entry.confidence_max,
                "associated_name": entry.expected_associated_name,
            }

        finding_data: dict[str, object] | None = None
        if finding is not None:
            view = FindingView.from_finding(
                finding,
                match=finding.match,
                context=finding.context,
            )
            finding_data = view.to_dict()

        return {
            "case_id": observation.case.case_id,
            "entry_id": entry.id if entry is not None else None,
            "known_problem": observation.known_problem,
            "file": observation.file_path,
            "line": observation.line,
            "source_line": observation.source_line,
            "expected": expected,
            "expectation_met": observation.expectation_met,
            "checks": {
                check.field: {
                    "status": check.status.value,
                    "expected": check.expected,
                    "actual": check.actual,
                }
                for check in observation.checks
            },
            "mismatches": [
                {
                    "field": mismatch.field,
                    "expected": mismatch.expected,
                    "actual": mismatch.actual,
                }
                for mismatch in observation.mismatches
            ],
            "finding": finding_data,
        }

    @staticmethod
    def _display_disposition(disposition: ExpectedDisposition) -> str:
        return "none" if disposition is NoFinding.NONE else disposition.value

    @staticmethod
    def _truncate_scanned_line(line: str) -> str:
        if len(line) <= MAX_SCANNED_LINE_CHARS:
            return line
        return line[: MAX_SCANNED_LINE_CHARS - 3] + "..."

    @staticmethod
    def _truncate_middle(value: str, max_chars: int) -> str:
        if len(value) <= max_chars:
            return value
        remaining = max_chars - 3
        prefix_length = (remaining + 1) // 2
        suffix_length = remaining // 2
        return value[:prefix_length] + "..." + value[-suffix_length:]

    @staticmethod
    def _cell(value: str) -> str:
        return str(value).replace("\\", "\\\\").replace("|", "\\|").replace(
            "\r", "\\r"
        ).replace("\n", "\\n")
