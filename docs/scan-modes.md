# Scan Modes

Secrets Hunter can detect secrets in files, git history, and exposed domain paths. The way a given target is collected and processed is called a **scan mode**.

> Each scan mode builds a collection of scan targets: files for filesystem scans, changed file blobs from selected commits for git history scans, and relative URL paths for domain scans.

Scan modes are separated from detection logic. They decide where content comes from, while the detection process decides whether that content contains secrets.

## Filesystem Scans

Filesystem scans read files or directories from disk. This is the default scan mode and is used when no git history or domain option is provided.

```bash
secrets-hunter .
```

## Git History Scans

Git history scans are enabled with `--git-revset`. Secrets Hunter uses a git revision expression to select commits, scans changed file blobs from those commits, and reports findings introduced on added lines. This mode requires git to be installed.

### Options

| Flag                      |   Type | Description                                                           |
|---------------------------|-------:|-----------------------------------------------------------------------|
| `--git-revset`            | string | Scan git history using commits selected by a git revision expression. |
| `--git-max-count`         |    int | Limit the number of commits selected by `--git-revset`.               |

### Example

```bash
secrets-hunter . --git-revset main..HEAD
```

## Domain Scans

Domain scans are enabled with `--domain`. Secrets Hunter builds a list of commonly exposed relative URL paths, fetches them from the target host, and scans successful text responses.

### Options

| Flag                      |   Type | Default | Description                                                           |
|---------------------------|-------:|--------:|-----------------------------------------------------------------------|
| `--domain`                | string |         | Scan commonly exposed paths on a host or domain.                      |
| `--skip-tls-verify`       |   bool | `False` | Skip TLS certificate verification for domain scans.                   |

### Example

```bash
secrets-hunter --domain example.com
```

> Filesystem scans, git history scans, and domain scans collect individual targets differently, but once text content is collected, it goes through the same detection process.

## Constraints

- `--git-max-count` requires `--git-revset`.
- `--git-max-count` must be greater than `0`.
- `--skip-tls-verify` requires `--domain`.
- `--domain` cannot be combined with `--git-revset`.
- `--domain` must be an HTTP(S) URL or plain domain.
