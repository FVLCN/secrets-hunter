# Secrets Hunter

Detect secrets and sensitive information in your codebase without noise.

## Features

- **Pattern-based detection**: Identifies known secret formats (API keys, tokens, etc.)
- **Entropy-based detection**: Finds high-entropy strings that might be secrets

## Installation

```bash
python -m venv venv
pip install -e .
```

## Usage

### Command Line

```bash
# Scan a file
secrets-hunter config.py

# Scan a directory
secrets-hunter /path/to/project

# Export to JSON
secrets-hunter /path/to/project --json results.json
```

### Python API

```python
from secrets_hunter import SecretsHunter
from secrets_hunter.config.settings import ScannerConfig

# Create scanner
config = ScannerConfig()
scanner = SecretsHunter(config)

# Scan a directory
findings = scanner.scan('/path/to/project')

# Process findings
for finding in findings:
    print(f"{finding['file']}:{finding['line']} - {finding['type']}")
```


## License

MIT
