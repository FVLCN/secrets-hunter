# Usage and Examples

Secrets Hunter runs scans from the command line:

```bash
secrets-hunter [OPTIONS] [target]
```

> If no target is provided, Secrets Hunter scans the current directory.

## Common Options

| Flag                      |   Type | Default | Description                                                           |
|---------------------------|-------:|--------:|-----------------------------------------------------------------------|
| `-h`, `--help`            |        |         | Show help and exit.                                                   |
| `--version`               |        |         | Show version and exit.                                                |
| `--config`                | path[] |         | Path to a TOML overlay config. Can be used multiple times.            |
| `--reveal-findings`       |   bool | `False` | Print raw matches in output.                                          |
| `--json`                  |   path |         | Export results to a JSON file.                                        |
| `--sarif`                 |   path |         | Export results to a SARIF file.                                       |
| `--truncate-long-matches` |   bool | `False` | Truncate long finding matches in output.                              |
| `--hex-entropy`           |  float |   `3.0` | Hex entropy threshold. Lower = more sensitive / more noise.           |
| `--b64-entropy`           |  float |  `4.25` | Base64 entropy threshold. Lower = more sensitive / more noise.        |
| `--min-length`            |    int |    `10` | Minimum candidate string length to consider.                          |
| `--workers`               |    int |     `4` | Number of parallel workers when scanning directories.                 |
| `--log-level`             |   enum |  `INFO` | Logging verbosity: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`.   |
| `--min-confidence`        |    int |     `0` | Only report findings with confidence **>=** this value (0–100).       |
| `--fail-on-findings`      |   bool | `False` | Exit with code `2` if a report contains non-rejected findings.        |

For git history and domain scan options, see [Scan Modes](https://docs.fvlcn.dev/secrets-hunter/scan-modes/).

## Filesystem scans

### Scan the current directory

```bash
secrets-hunter .
```

Example output:

```bash
========================================================================================
[1] Hardcoded jwt secret token at server.js:3
    Severity:   CRITICAL (confidence: 100%, reasoning: Pattern Match)
    Variable:   jwt_secret_token
    Match:      ***MASKED***
    Context:    ***MASKED***
----------------------------------------------------------------------------------------
[2] Hardcoded aws access key at app.py:6
    Severity:   CRITICAL (confidence: 100%, reasoning: Pattern Match)
    Variable:   aws_access_key
    Match:      ***MASKED***
    Context:    ***MASKED***
----------------------------------------------------------------------------------------
[3] Hardcoded aws secret access key at app.py:7
    Severity:   CRITICAL (confidence: 100%, reasoning: High Entropy in context of secret key/variable assignment - secret)
    Variable:   aws_secret_access_key
    Match:      ***MASKED***
    Context:    ***MASKED***
----------------------------------------------------------------------------------------
[4] Hardcoded build id at app.py:10
    Severity:   INFO (confidence: 0%, reasoning: SHA1 hash in value)
    Variable:   build_id
    Match:      ***MASKED***
    Context:    ***MASKED***
----------------------------------------------------------------------------------------
```

### Scan a directory

```bash
secrets-hunter path/to/project
```

### Scan a directory with Docker

Mount the directory you want to scan and pass the mounted path as the target:

```bash
docker run --rm -v ~/projects/my-app:/scan ghcr.io/fvlcn/secrets-hunter:latest /scan
```

### Scan a single file

```bash
secrets-hunter path/to/file.py
```

## Git History scans

Git history scans use `--git-revset`, which accepts a git revision expression. It is not parsed as arbitrary `git rev-list` options.

### Scan a commit

Use `<commit-sha>^!` to scan only one commit:

```bash
secrets-hunter . --git-revset '<commit-sha>^!'
```

### Scan a pull request

Scan commits that are on the current branch but not on `main`:

```bash
secrets-hunter . --git-revset main..HEAD
```

Replace `main` with the base branch if needed.

### Scan branch history

Scan the last 20 commits reachable from `HEAD`:

```bash
secrets-hunter . --git-revset HEAD --git-max-count 20
```

### Scan git history with Docker

Mount the repository, set it as the working directory, and mark the mounted path as a safe Git directory inside the container:

```bash
docker run --rm \
  -e GIT_CONFIG_COUNT=1 \
  -e GIT_CONFIG_KEY_0=safe.directory \
  -e GIT_CONFIG_VALUE_0=/scan \
  -v ~/projects/my-app:/scan \
  -w /scan \
  ghcr.io/fvlcn/secrets-hunter:latest \
  . --git-revset main..HEAD
```

## Domain scans

Domain scans check the built-in list of commonly exposed relative paths on the target host.

### Scan exposed domain paths

```bash
secrets-hunter --domain example.com
```

### Scan exposed domain paths with Docker

Domain scans do not need a mounted local directory:

```bash
docker run --rm ghcr.io/fvlcn/secrets-hunter:latest --domain example.com
```

### Skip TLS verification

For internal or controlled environments with custom TLS, certificate verification can be skipped:

```bash
secrets-hunter --domain https://internal.example --skip-tls-verify
```

## Output and Filtering

### Reveal findings

Findings are masked by default. To show raw values, use the `--reveal-findings` flag:

```bash
secrets-hunter . --reveal-findings
```

### Export as JSON

```bash
secrets-hunter . --json results.json
```

Example output:

```json
[
    {
        "title": "Hardcoded jwt secret token at server.js:3",
        "file": "server.js",
        "line": 3,
        "type": "JWT Token",
        "match": "***MASKED***",
        "context": "***MASKED***",
        "severity": "CRITICAL",
        "confidence_reasoning": "Pattern Match",
        "detection_method": "pattern",
        "confidence": 100,
        "context_var": "jwt_secret_token",
        "commit": null,
        "vulnerable_url": null
    }
]
```

### Export as JSON and reveal findings

```bash
secrets-hunter . --reveal-findings --json results.json
```

### Export as JSON, reveal findings and truncate long matches

```bash
secrets-hunter . --reveal-findings --json results.json --truncate-long-matches
```

### Export as JSON, reveal findings and filter out low-confidence findings

```bash
secrets-hunter . --reveal-findings --json results.json --min-confidence 75
```

### Export as SARIF

```bash
secrets-hunter . --sarif results.sarif
```

### Fail only on higher-confidence findings

```bash
secrets-hunter . --min-confidence 75 --fail-on-findings
```

## Config

### Use overlay config

Apply custom configuration using an overlay file:

```bash
secrets-hunter . --config team.toml
```

### Stack multiple overlays

Apply multiple configuration files in sequence:

```bash
secrets-hunter . --config ci.toml --config local.toml
```

Learn more about configuration in the [Configuration docs](https://docs.fvlcn.dev/secrets-hunter/config/).

## Exit Codes

- `0` - scan completed successfully. Findings may still be present unless `--fail-on-findings` is used.
- `1` - scan failed because of an input or runtime error.
- `2` - scan completed successfully and actionable findings were reported while `--fail-on-findings` was set.
