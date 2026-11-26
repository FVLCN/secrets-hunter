# Benchmark

Manually maintained cases for checking secret detection:

- `cases/positive/`: secrets the scanner should detect.
- `cases/negative/`: non-secret values the scanner should leave unreported.

## Run

From the repository root:

    PYTHONPATH=src python3 benchmark/run_benchmark.py

The table shows each entry's expected disposition, actual confidence, source
line, and check result. Failed checks and unexpected findings appear below it.

To save a JSON report and print a short summary:

    PYTHONPATH=src python3 benchmark/run_benchmark.py --json path/to/report.json

JSON includes case metadata, checks, mismatches, findings, and a case-data
checksum. It contains fixture values and source lines.

Visualize the benchmark report at [https://fvlcn.dev/secrets-hunter/benchmark/](https://fvlcn.dev/secrets-hunter/benchmark/).

## Add a case

Create a TOML file in either category, following an existing case. Include
source text in `[[files]]` and one or more `[[entries]]` with:

- `id`, `file`, `line`, and the exact `value`.
- `expected_disposition`: `report`, `review`, `reject`, or `no_finding`.
- `expected_associated_name`: the expected identifier, or `""` for no name.

`no_finding` requires the scanner to produce no finding for that entry.
Optional `confidence_min` and `confidence_max` set inclusive score bounds;
omitted endpoints default to 0 and 100. Omit both to skip the confidence check.

For a known gap, record the desired result and set `known_problem = true`.
Failures remain visible as `✗*` and in JSON, but are excluded from the console
error list and do not fail the benchmark. Keep the entry after it is fixed.
Other failed expectations and unexpected findings produce a nonzero exit code.

Fixture credentials are synthetic, unprovisioned, or publicly documented test values.
