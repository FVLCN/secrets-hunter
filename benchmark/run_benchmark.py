#!/usr/bin/env python3
"""Run the manually curated positive, negative, and known-gap benchmark."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

if not __package__:
    # Keep ``python benchmark/run_benchmark.py`` working as well as module use.
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from benchmark.benchmark import Benchmark
from benchmark.presentation import BenchmarkPresentation


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--json",
        type=Path,
        metavar="PATH",
        help="write the complete benchmark report as JSON and print a short summary",
    )
    args = parser.parse_args(argv)

    report = Benchmark().run()
    if args.json is not None:
        BenchmarkPresentation.write_json_report(report, args.json)
        BenchmarkPresentation.render_json_summary(report, args.json)
    else:
        BenchmarkPresentation.render_console(report)
    return 0 if report.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
