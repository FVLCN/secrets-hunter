# Usage

**Secrets Hunter** scans a **file** or a **directory**:

```bash
secrets-hunter [OPTIONS] [target]
```

- **target**: file or directory to scan (default: current directory `.`)

## Options

| Flag                      |    Type | Default | Description                                                          |
|---------------------------|--------:|--------:|----------------------------------------------------------------------|
| `-h`, `--help`            |         |         | Show help and exit.                                                  |
| `--reveal-findings`       |    bool | `False` | Print raw matches in output.                                         |
| `--config`                |  path[] |         | Path to a TOML overlay config. Can be used multiple times.           |
| `--json`                  |    path |         | Export results to a JSON file.                                       |
| `--sarif`                 |    path |         | Export results to a SARIF file.                                      |
| `--truncate-long-matches` |    bool | `False` | Truncate long finding matches in output.                             |
| `--hex-entropy`           |   float |   `3.0` | Hex entropy threshold. Lower = more sensitive / more noise.          |
| `--b64-entropy`           |   float |  `4.25` | Base64 entropy threshold. Lower = more sensitive / more noise.       |
| `--min-length`            |     int |    `10` | Minimum candidate string length to consider.                         |
| `--workers`               |     int |     `4` | Number of parallel workers when scanning directories.                |
| `--log-level`             |    enum |  `INFO` | Logging verbosity: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`.  |
| `--min-confidence`        |     int |     `0` | Only report findings with confidence **>=** this value (0–100).      |
| `--fail-on-findings`      |    bool | `False` | Exit with code `2` if a report contains non-rejected findings.       |

---

## Usage examples

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

### Scan a single file

```bash
secrets-hunter path/to/file.py
```

### Reveal findings (unmasked)
Findings are masked by default. To show raw values, use the `--reveal-findings` flag:

```bash
secrets-hunter . --reveal-findings
```

Example output:

```bash
========================================================================================
[1] Hardcoded jwt secret token at server.js:3
    Severity:   CRITICAL (confidence: 100%, reasoning: Pattern Match)
    Variable:   jwt_secret_token
    Match:      eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xxxxxxxxxx.xxxxxxx...
    Context:    const JWT_SECRET_TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xxxxxx'
----------------------------------------------------------------------------------------
[2] Hardcoded aws access key at app.py:6
    Severity:   CRITICAL (confidence: 100%, reasoning: Pattern Match)
    Variable:   aws_access_key
    Match:      AKIAxxxxxxxxxxxxxxxx
    Context:    AWS_ACCESS_KEY = "AKIAxxxxxxxxxxxxxxxx"
----------------------------------------------------------------------------------------
[3] Hardcoded aws secret access key at app.py:7
    Severity:   CRITICAL (confidence: 100%, reasoning: High Entropy in context of secret key/variable assignment - secret)
    Variable:   aws_secret_access_key
    Match:      xxxxxxxxxxxxx/xxxxxxx/xxxxxxxxxxxxxxxxxx
    Context:    AWS_SECRET_ACCESS_KEY = "xxxxxxxxxxxxx/xxxxxxx/xxxxxxxxxxxxxxxxxx"
----------------------------------------------------------------------------------------
[4] Hardcoded build id at app.py:10
    Severity:   INFO (confidence: 0%, reasoning: SHA1 hash in value)
    Variable:   build_id
    Match:      xxxxxxxx
    Context:    BUILD_ID = "xxxxxxxx"
----------------------------------------------------------------------------------------
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
        "context_var": "jwt_secret_token"
    },
    {
        "title": "Hardcoded aws access key at app.py:6",
        "file": "app.py",
        "line": 6,
        "type": "AWS Access Key",
        "match": "***MASKED***",
        "context": "***MASKED***",
        "severity": "CRITICAL",
        "confidence_reasoning": "Pattern Match",
        "detection_method": "pattern",
        "confidence": 100,
        "context_var": "aws_access_key"
    },
    {
        "title": "Hardcoded aws secret access key at app.py:7",
        "file": "app.py",
        "line": 7,
        "type": "High Entropy Base64 String",
        "match": "***MASKED***",
        "context": "***MASKED***",
        "severity": "CRITICAL",
        "confidence_reasoning": "High Entropy in context of secret key/variable assignment - secret",
        "detection_method": "entropy",
        "confidence": 100,
        "context_var": "aws_secret_access_key"
    },
    {
        "title": "Hardcoded build id at app.py:10",
        "file": "app.py",
        "line": 10,
        "type": "High Entropy Hex String",
        "match": "***MASKED***",
        "context": "***MASKED***",
        "severity": "INFO",
        "confidence_reasoning": "SHA1 hash in value",
        "detection_method": "entropy",
        "confidence": 0,
        "context_var": "build_id"
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

---

## Exit codes

- `0` - scan succeeded and no actionable findings remained
- `1` - scan failed because of an input/runtime error
- `2` - scan succeeded and actionable findings were reported while `--fail-on-findings` was set

---

## Logging

### Debug output

```bash
secrets-hunter . --log-level DEBUG
```

---
