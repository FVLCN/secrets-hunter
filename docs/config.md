# Configuration

Secrets Hunter loads two **packaged** config files:

- `patterns.toml` (regex patterns, keywords, assignment patterns, excludes)
- `ignore.toml` (ignored files, extensions, and directories)

You can then apply **one or more overlay TOML files** via CLI:

```bash
secrets-hunter . --config team-overrides.toml
```

> Overlays are applied **in the order provided**. Overlays don't replace the entire configuration, but merge on top of existing settings instead.

## Viewing Current Configuration

The `showconfig` command displays the scanner's active configuration. You can view the complete configuration or specific sections.

View the entire configuration:

```bash
secrets-hunter showconfig
```

View specific configuration sections:

```bash
# Shows secret pattern definitions
secrets-hunter showconfig secret_patterns

# Shows ignored directories and files
secrets-hunter showconfig ignore_files ignore_dirs
```

If an overlay file is provided, `showconfig` displays the merged result of the default configuration plus your overrides:

```bash
# Shows complete config with team overrides applied
secrets-hunter showconfig --config team-overrides.toml

# Shows only secret patterns with overrides applied
secrets-hunter showconfig secret_patterns --config team-overrides.toml
```

## Full Schema

### Pattern table

A reusable schema for defining regex-based patterns.

**Fields:**
- `name` — non-empty string
- `pattern` — non-empty string, compiled as a regular expression
- `flags` *(optional)* — list of strings, each one of:
  - `IGNORECASE`
  - `MULTILINE`
  - `DOTALL`
  - `VERBOSE`
  - `ASCII`

> Prefer specific patterns over broad ones — broad regex means noisy scans. Pattern names appear in reports, so make them descriptive.

### Secret patterns

Patterns used for secret detection.

```toml
[[secret_patterns]]
name = "GitLab Personal Access Token"
pattern = '''\bglpat-[A-Za-z0-9_-]{20}\b'''
# Optional:
# flags = ["IGNORECASE", "MULTILINE", "DOTALL", "VERBOSE", "ASCII"]
```

Notes:
- Uses the [Pattern table](#pattern-table) schema

### Exclude patterns

Findings matching these patterns will be rejected.

> Keep `exclude_patterns` tight; avoid excluding generic words unless you really need it.

```toml
[[exclude_patterns]]
name = "MD5"
category = "hash"
pattern = '''\b[0-9a-f]{32}\b'''

[[exclude_patterns]]
name = "dummy"
category = "placeholder"
pattern = 'dummy'
# Optional:
# flags = ["IGNORECASE"]
```

Notes:
- Uses the [Pattern table](#pattern-table) schema
- Additional field:
  - `category` — used for reporting and grouping

### Secret keywords

Used to boost confidence when a match is associated with a variable name suggesting a secret.

```toml
secret_keywords = [
  "secret",
  "token",
  "api_key",
  "password"
]
```

### Exclude keywords

Used to reject findings based on keyword/variable name.

```toml
exclude_keywords = [
  "integrity",
  "hash"
]
```

### Assignment patterns

Used to associate candidate values with variable or key names (e.g. `API_KEY="..."`).
Each regex must capture the variable or key name in group 1 and the candidate value in group 2.

```toml
assignment_patterns = [
  '''([a-zA-Z_][a-zA-Z0-9_]*)\s*[:=]\s*["']([^"']+)["']''',
  '''export\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*[:=]\s*["']([^"']+)["']'''
]
```

### Ignore rules

Ignore rules live under the `[ignore]` table:

```toml
[ignore]
files = ["package-lock.json"]
extensions = [".pdf", ".png", ".zip"]
dirs = ["node_modules", ".git", "dist", "build"]
```

## Overlays

### Arrays of tables

Tables in the array are merged by `name` during overlay processing:

- If an overlay defines a pattern with an existing `name`, it **replaces** the previous pattern.
- If it uses a new `name`, it **adds** a new pattern.
- You can remove existing patterns using a `remove_*` key.

Applies to:
- `secret_patterns`
- `exclude_patterns`

### Lists of strings

These keys are treated as lists of strings and are:

1. **extended** (appended) from each file in load order
2. **deduplicated** (first occurrence kept)

Applies to:
- `secret_keywords`
- `exclude_keywords`
- `assignment_patterns`
- `ignore.files`
- `ignore.extensions`
- `ignore.dirs`

> [!WARNING]
> Lists can’t be overridden — only appended and deduplicated (first occurrence wins). To undo something from an earlier file, use the matching `remove_*` key.

### Removals

If you need to remove a previously added item, use the corresponding `remove_*` key.

> Within each config file, removals are applied before additions.

If the same overlay removes and adds the same item, the added item remains. To remove something added by another overlay, place the removal in a later overlay file.

Supported removal keys:

- `remove_secret_patterns`
- `remove_exclude_patterns`
- `remove_secret_keywords`
- `remove_exclude_keywords`
- `remove_assignment_patterns`
- `remove_ignore_files`
- `remove_ignore_extensions`
- `remove_ignore_dirs`

Remove patterns by name:

```toml
remove_secret_patterns = ["AWS Access Key ID", "JWT Token"]
remove_exclude_patterns = ["MD5", "dummy"]
```

Remove keywords and assignment patterns by exact string match:

```toml
remove_secret_keywords = ["key"]
remove_exclude_keywords = ["hash"]
remove_assignment_patterns = [
  '''set\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*[:=]\s*["']([^"']+)["']''',
]
```

Remove ignore items:

```toml
remove_ignore_files = ["package-lock.json"]
remove_ignore_extensions = [".pdf", ".svg"]
remove_ignore_dirs = ["dist"]
```

## Practical Examples

### 1) Minimal overlay: add one pattern + ignore a dir

**minimal.toml**

```toml
[[secret_patterns]]
name = "My Service Token"
pattern = '''\bmytok_[A-Za-z0-9]{32,}\b'''

[ignore]
dirs = ["vendor"]
```

Run:

```bash
secrets-hunter . --config minimal.toml
```

### 2) Override an existing pattern by name

**override_stripe_live_only.toml**

```toml
[[secret_patterns]]
name = "Stripe API Key" # same name => overrides packaged one
pattern = '''\bsk_live_[A-Za-z0-9]{24,}\b'''
flags = ["ASCII"]
```

Run:

```bash
secrets-hunter . --config override_stripe_live_only.toml
```

### 3) Remove a built-in pattern

**remove_aws_access_key_id.toml**

```toml
remove_secret_patterns = ["AWS Access Key ID"]
```

Run:

```bash
secrets-hunter . --config remove_aws_access_key_id.toml
```

### 4) Team baseline overlay

**team.toml**

```toml
# 1) Add/override exclusion patterns
[[exclude_patterns]]
name = "dummy"
category = "placeholder"
pattern = 'dummy'

# your internal non-secret format
[[exclude_patterns]]
name = "ACME build ID"
category = "internal"
pattern = '''\bACME_BUILD_ID_[0-9]{8}\b'''

# 2) Add/override secret patterns
[[secret_patterns]]
name = "My Service Token"
pattern = '''\bmytok_[A-Za-z0-9]{32,}\b'''

# 3) Ignore rules
[ignore]
dirs = [
  "node_modules",
  "dist",
  "build",
  ".venv",
]

extensions = [
  ".min.js",
  ".map",
]
```

Run:

```bash
secrets-hunter . --config team.toml
```

### 5) Let local scans show findings that CI suppresses

**ci.toml**

```toml
[[exclude_patterns]]
name = "example"
category = "placeholder"
pattern = 'example'

[[exclude_patterns]]
name = "test"
category = "placeholder"
pattern = 'test'
```

**local.toml**

```toml
remove_exclude_patterns = ["test"] # let local show "test" matches
```

Run:

```bash
secrets-hunter . --config ci.toml --config local.toml
```

Configs are layered in the order given: `ci.toml` first, then `local.toml`. Because `local.toml` removes the `test` exclude pattern, local scans will report matches that CI would suppress.
