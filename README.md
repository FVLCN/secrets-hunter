# Secrets Hunter

Detect secrets and sensitive information in your codebase without noise.

## Features

- **Pattern-based detection**: Identifies predefined secret formats (API keys, tokens, etc.)
- **Entropy-based detection**: Finds high-entropy strings that might be secrets

## Installation

```bash
python -m venv venv
source venv/bin/activate
pip install -e .
```

## Usage

### Command Line

```bash
# Scan a file
secrets-hunter app.py

# Scan a directory
secrets-hunter /path/to/project

# Export to JSON
secrets-hunter /path/to/project --json results.json
```

## License

MIT
