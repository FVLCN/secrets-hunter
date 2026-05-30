# Secrets Hunter

[![PyPI](badges/pypi.svg)](https://pypi.org/project/secrets-hunter/)
[![Python](badges/python.svg)](https://python.org/)

**Secrets Hunter** is a lightweight, fully autonomous, and dependency-free scanner that detects secrets across filesystems, git history, and exposed domain paths.

It is language agnostic and works on text content rather than language-specific syntax, which makes it suitable for finding secrets in mixed repositories, configuration files, scripts, and infrastructure code.

> [!WARNING]
> Secrets Hunter is intended for defensive security work. Do not use it to scan third-party systems, domains, repositories, or infrastructure without permission.

Scans do not require external dependencies to run, though git must be installed to scan git history. You can run scans from the command line, wire them into git hooks for local development, or automate them in CI to act as a security gate.

## Save Time With Smarter Secret Detection

Secrets Hunter is built around a simple principle: only surface findings that are actually worth reviewing.

Consider these two lines:

```text
api_token = "79ffdc174191ed0f2d01d465c10c80c8c9542cb9"
hash = "79ffdc174191ed0f2d01d465c10c80c8c9542cb9"
```

The first line looks extremely suspicious: it is a high-entropy hex string assigned to the `api_token` variable, whose name suggests the value is a secret. And most likely, it is. The second line is just a random hash, so it is not even worth considering.

However, in this line:

```text
api_token = "123abc456def"
```

even though the variable name suggests it is a secret, the assigned value suggests that it is not. Despite having high hex entropy, this is a placeholder or fake secret, not something worth attention. Therefore, it should not be reported as an actionable finding.

Secrets are detected using a combined **regex** and **entropy** approach, though the list of built-in regex patterns is intentionally kept short for three reasons:

- The number of existing secret formats is huge, so large regex catalogs can slow down scans and become hard to maintain.
- Secret formats often overlap, so the provider cannot always be identified reliably.
- Most such secrets are high-entropy strings anyway.

There are a few exceptions to this, such as PEM keys, database connection strings, secrets with unusual character sets, or low-entropy secrets. This is where regex patterns come in handy.

A good example is an AWS access key ID, which has a recognizable `AKIA...` shape but may fall below the entropy threshold:

```text
aws_access_key_id = "AKIA9Z4X7Q2M8V6N3P1L"
```

In this case, entropy alone may not be enough, so Secrets Hunter uses a regex pattern to catch the fixed `AKIA...` format.

Regex matches still go through the same context and rejection checks. For example:

```text
aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"
```

matches the AWS access key ID shape, but is rejected because it contains a known example placeholder. It is not treated as an actionable finding.

For a deeper explanation of how regex patterns, entropy checks, assignment context, rejection rules, and scan modes work together, see the [Scan Modes](https://docs.fvlcn.dev/secrets-hunter/scan-modes/) and [Detection Process](https://docs.fvlcn.dev/secrets-hunter/detection-process/) docs.

## Installation

> Requires Python 3.11 or newer.

Secrets Hunter can be installed via PyPI, from source, or using Docker. For a quick start, install directly from PyPI:

```bash
pip install secrets-hunter
```

For installation from source or Docker, see the [Installation docs](https://docs.fvlcn.dev/secrets-hunter/installation/).

## Quick Start

Use `secrets-hunter` with a local target for filesystem scans, `--git-revset` for git history, or `--domain` for exposed domain paths.

Scan the current directory:

```bash
secrets-hunter .
```

Scan a specific file:

```bash
secrets-hunter path/to/file.py
```

Scan git history using a git revision expression:

```bash
secrets-hunter . --git-revset main..HEAD
```

Scan commonly exposed domain paths:

```bash
secrets-hunter --domain example.com
```

Findings are masked by default. To reveal them, use `--reveal-findings`:

```bash
secrets-hunter . --reveal-findings
```

Export results to JSON or SARIF:

```bash
secrets-hunter . --json results.json
secrets-hunter . --sarif results.sarif
```

Fail with exit code `2` when actionable findings are present:

```bash
secrets-hunter . --min-confidence 75 --fail-on-findings
```

See the [Usage and Examples docs](https://docs.fvlcn.dev/secrets-hunter/usage-and-examples/) for all flags and more examples.

## Configuration

Secrets Hunter ships with built-in packaged defaults. You can display them using the CLI:

```bash
secrets-hunter showconfig
```

The detection behavior described above is configurable. Secret patterns, secret keywords, false-positive rules, and ignore rules can be adjusted with TOML configuration overlays.

Example team baseline overlay:

```bash
secrets-hunter . --config team.toml
```

Multiple overlays are applied **in the order provided**:

```bash
secrets-hunter . --config ci.toml --config local.toml
```

A full description and usage examples are available in [Configuration docs](https://docs.fvlcn.dev/secrets-hunter/config/).

## License

Secrets Hunter is released under the MIT License, meaning you are free to use, modify, and distribute it for both personal and commercial purposes.

## Acknowledgments

This project was made possible by [whitespots.io](https://whitespots.io).

Special thanks to [@Shandriuk](https://github.com/Shandriuk) for implementing the end-to-end functional testing suite.
