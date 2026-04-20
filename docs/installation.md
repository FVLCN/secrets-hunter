# Installation

Secrets Hunter can be installed in three ways: via PyPI, from source, or via Docker.

> **Requirements:** Python 3.11+

## From PyPI

The simplest way to get started. Install the latest stable release directly from the Python Package Index:
```bash
pip install secrets-hunter
```

To upgrade an existing installation to the latest version:
```bash
pip install --upgrade secrets-hunter
```

## From Source

Installing from source is recommended if you want to contribute to the project or run the latest unreleased changes.

### 1. Clone the repository
```bash
git clone https://github.com/FVLCN/secrets-hunter.git secrets-hunter
cd secrets-hunter
```

### 2. Create and activate a virtual environment

**macOS and Linux:**
```bash
python -m venv venv
source venv/bin/activate
```

**Windows:**
```bash
python -m venv venv
venv\Scripts\activate
```

### 3. Build the package
```bash
pip install -e .
```

The `-e` flag installs the package in editable mode, meaning any changes you make to the source code will be reflected immediately without reinstalling.

## From Docker

Docker is the recommended approach if you want to run Secrets Hunter without installing Python on your host machine. Images are hosted on the [GitHub Container Registry (GHCR)](https://github.com/FVLCN/secrets-hunter/pkgs/container/secrets-hunter).

### Pull the image

Pull the latest version:
```bash
docker pull ghcr.io/fvlcn/secrets-hunter:latest
```

### Verify the installation

```bash
docker run --rm ghcr.io/fvlcn/secrets-hunter:latest --version
```

### Run a scan

Mount the directory you want to scan as a volume and pass it as an argument:
```bash
docker run --rm -v ~/projects/my-app:/scan ghcr.io/fvlcn/secrets-hunter:latest /scan
```
