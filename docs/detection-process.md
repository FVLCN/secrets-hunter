# Detection Process

The detection process handles three kinds of candidates:

- generic strings
- PEM keys
- database connection strings

Secrets Hunter handles different candidate types differently. PEM keys and database connection strings have recognizable structure, while generic string candidates are usually detected through entropy and assignment context. The scanner also uses regex matches for some cases, such as low entropy secrets or secrets with non-standard character sets.

## Process Overview

For each collected text target, the scanner extracts candidate fragments, runs entropy and pattern detection, merges the findings, then processes context and confidence before preparing results for output.

The detection flow can be described by the following diagram:

```text
                    ┌─────────────────────────────┐
                    │ Text content from scan mode │
                    └───────────────┬─────────────┘
                                    │
                    ┌───────────────▼─────────────┐
                    │ Extract candidate fragments │
                    └──┬────────────┬───────────┬─┘
                       │            │           │
                       │     ┌──────▼──────┐    │
        ┌──────────────▼──┐  │   Generic   │  ┌─▼───────────────┐
        │    PEM keys     │  │   strings   │  │ DB conn. strings│
        └──────────────┬──┘  │             │  └─┬───────────────┘
                       │     └──────┬──────┘    │
                       │            │           │
                       └────────────┼───────────┘
                                    │
                 ┌──────────────────▼──────────────────┐
                 │           Run detectors             │
                 │         entropy + patterns          │
                 └──────────────────┬──────────────────┘
                                    │
                 ┌──────────────────▼──────────────────┐
                 │           Merge findings            │
                 │        prefer pattern matches       │
                 └──────────────────┬──────────────────┘
                                    │
                 ┌──────────────────▼──────────────────┐
                 │ Process context, rejection &        │
                 │ confidence                          │
                 │                                     │
                 │ · check value false-positive rules  │
                 │ · find assignment/key-value context │
                 └──┬───────────────────────────────┬──┘
                    │                               │
                    │                     ┌─────────▼─────────────────┐
                    │                     │   With assignment context │
         ┌──────────▼──────────┐          │                           │
         │  Without assignment │          │  · entropy: assignment    │
         │  context            │          │    context boost          │
         │                     │          │  · mark keyword-based     │
         │  · mark value-based │          │    false positives        │
         │    false positives  │          │  · mark value false pos.  │
         │                     │          │    (unless secret-like)   │
         └─────────┬───────────┘          │  · entropy: secret-       │
                   │                      │    keyword boost          │
                   │                      └─────────┬─────────────────┘
                   │                                │
                   └────────────────┬───────────────┘
                                    │
                  ┌─────────────────▼────────────────┐
                  │  Prepare findings for output     │
                  │                                  │
                  │   · Confidence filtering         │
                  │   · Truncation                   │
                  │   · Masking                      │
                  └──────────────────────────────────┘
```

The following sections describe how each candidate type is detected and what causes a finding to be rejected.

## Generic Candidates

Generic candidates are arbitrary string values such as API keys, tokens, and passwords. They are detected through entropy checks or regex patterns, and the surrounding assignment or key/value context is then used to adjust confidence and reject false positives.

Consider this text block:

```text
api_key = "qF7xN2pL9vR4sT8mK3zY6dH1wC5bJ0uA"
value = "qF7xN2pL9vR4sT8mK3zY6dH1wC5bJ0uA"
asset_integrity = "qF7xN2pL9vR4sT8mK3zY6dH1wC5bJ0uA"
```

Even though the assigned value is the same, the assignment context changes its meaning completely:

- `api_key` certainly identifies the value as a secret.
- `value` gives no context hinting at a secret, so further investigation is required.
- `asset_integrity` clearly suggests a non-secret context, so the finding is marked as a false positive.

In these examples, the variable name drives the confidence — the scanner uses it to treat the finding as actionable, flag it for further review, or mark it as a false positive.

However, the value itself can also affect the scanner's confidence. For example:

```text
value = "c12ddf3bfeeda5a2f7dd28feee62e1d3afaf097c"
```

This string has high entropy and assignment context, but it also matches the shape of a SHA1 hash, which is a common artifact of build systems and version control, not a hardcoded secret.

> Secrets Hunter treats known hash formats as false positives unless the surrounding context identifies the value as a secret.

Placeholder values are treated differently — they are always rejected, regardless of the surrounding context. Consider these two lines:

```text
secret = "123abc456def"
aws_access_key = "AKIAIOSFODNN7EXAMPLE"
```

Despite the secret-identifying variable names, both values are rejected: `123abc456def` matches a known placeholder pattern, and `AKIAIOSFODNN7EXAMPLE` contains a known example placeholder used in AWS documentation. In both cases, the variable name makes no difference.

The built-in patterns, keywords, and assignment rules can be inspected with `secrets-hunter showconfig`, or customized through a [configuration overlay](https://docs.fvlcn.dev/secrets-hunter/config/).

## PEM Keys

PEM blocks are detected by header/footer patterns. When Secrets Hunter sees a supported PEM header, it collects the whole block up to the matching footer and treats that block as one candidate.

> For well-formed PEM blocks the body lines are not reported as separate findings.

A key is treated as actionable when it looks like private key material: it has a supported private-key header, a matching footer, and a base64 body that can be decoded.

Example:

```text
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAJqRw7USOB2KRO3K1faJP5X2raZhHitmFBIjjnfAxivAAAAKgpZj7/KWY+
/wAAAAtzc2gtZWQyNTUxOQAAACAJqRw7USOB2KRO3K1faJP5X2raZhHitmFBIjjnfAxivA
AAAEDYfn9ZgXwunqZCBla+H8+F5hggplLpxqgprYTFwfv0MAmpHDtRI4HYpE7crV9ok/lf
atpmEeK2YUEiOOd8DGK8AAAAIXN0YXRlYW5kcHJvdmVATWFjQm9vay1BaXItMi5sb2NhbA
ECAwQ=
-----END OPENSSH PRIVATE KEY-----
```

Inline PEM blocks are also detected when the supported header and matching footer appear on the same line.

Example inline private key:

```text
-----BEGIN OPENSSH PRIVATE KEY-----b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZWQyNTUxOQAAACAJqRw7USOB2KRO3K1faJP5X2raZhHitmFBIjjnfAxivAAAAKgpZj7/KWY+/wAAAAtzc2gtZWQyNTUxOQAAACAJqRw7USOB2KRO3K1faJP5X2raZhHitmFBIjjnfAxivAAAAEDYfn9ZgXwunqZCBla+H8+F5hggplLpxqgprYTFwfv0MAmpHDtRI4HYpE7crV9ok/lfatpmEeK2YUEiOOd8DGK8AAAAIXN0YXRlYW5kcHJvdmVATWFjQm9vay1BaXItMi5sb2NhbAECAwQ=-----END OPENSSH PRIVATE KEY-----
```

### Rejection

Some PEM blocks are rejected instead of being treated as actionable findings:

- Public keys and certificates are not secret material and are rejected as false positives.
- Blocks where the footer is missing or doesn't match the header type are rejected as malformed.
- Blocks whose body is not valid base64, or decodes to something too short to be a real key, are rejected as malformed.

Example inline missing footer:

```text
PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----MIICXQIBAAKBgQDAwmJKDNZadDYMkkLRFL6B1/ZJ3fN3AqNiXy0N7YTa8Qaozu..."
```

Example invalid base64 body:

```text
-----BEGIN RSA PRIVATE KEY-----your_key_goes_here-----END RSA PRIVATE KEY-----
```

Example missing footer:

```text
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAACFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAgEA37a60AuK/dgXtxyVgnvrE7LGs9zX/bJuy0eBuKpn03m3cMZFhPWI
Xz+q6CU9cR1H5wqvtHoOqLKajo9iB6XYjPlpw8b2mvc66UPGFCUEMoWxzf3QdFXfU/veaG
```

Example mismatched footer:

```text
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAACFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAgEA37a60AuK/dgXtxyVgnvrE7LGs9zX/bJuy0eBuKpn03m3cMZFhPWI
Xz+q6CU9cR1H5wqvtHoOqLKajo9iB6XYjPlpw8b2mvc66UPGFCUEMoWxzf3QdFXfU/veaG
-----END RSA PRIVATE KEY-----
```

For PEM blocks with a missing or mismatched footer, Secrets Hunter replays the lines it consumed after the PEM header. Those replayed lines are scanned normally as generic strings and can still produce low-confidence entropy findings.

## Database Connection Strings

Database connection strings are detected by matching known URI schemes. Secrets Hunter looks for URI schemes with an embedded username and password, then treats the full URI as one candidate.

Example:

```text
DATABASE_URL="postgres://app_user:S3cr3tPassw0rd!@db.example.com:5432/app"
```

A connection URI is treated as actionable only when it contains an embedded password before the host.

### Rejection

The password field is subject to the same placeholder rules as generic candidates. A password like `{password}` or `%s` matches a template pattern, while a password like `example` matches a known placeholder word.

Example template URI:

```text
DATABASE_URL="postgresql://%s:%s@%s:%s/%s"
```

Example template password:

```text
DATABASE_URL="postgres://app_user:{password}@db.example.com:5432/app"
```

Example placeholder password:

```text
DATABASE_URL="postgres://app_user:example@db.example.com:5432/app"
```

## Confidence

Findings are assigned confidence based on detection method, assignment context, secret-like keywords, and false-positive checks.

> Confidence is used for prioritization and filtering; it does not mean the scanner has validated that a credential is live.

| Confidence | Severity   | Meaning                                                    |
|------------|------------|------------------------------------------------------------|
| `0`        | `INFO`     | Rejected / false positive                                  |
| `5`        | `LOW`      | High entropy without assignment context                    |
| `75`       | `MEDIUM`   | High entropy with assignment context                       |
| `100`      | `CRITICAL` | Pattern match or high-entropy value in secret-like context |


## Output

Before findings are reported, Secrets Hunter prepares them for output. This includes confidence filtering, optional truncation, and masking.

### Filtering

`--min-confidence` controls which findings are included in the report. By default, the threshold is `0`, so rejected results are still shown, which is useful for understanding why they were rejected. Raising the threshold hides lower-confidence findings.

```bash
secrets-hunter . --min-confidence 75
```

### Masking

> Findings are masked by default so scan results can be used safely in terminals, logs, and CI systems.

Use `--reveal-findings` only when raw values are needed.

```bash
secrets-hunter . --reveal-findings
```

### Truncation

Long findings can be truncated with `--truncate-long-matches`. PEM keys are truncated in a structure-aware way: Secrets Hunter keeps the header, the first body lines, the last body lines, and the footer.

```bash
secrets-hunter . --reveal-findings --truncate-long-matches
```

Example truncated PEM output:

```text
-----BEGIN RSA PRIVATE KEY-----
MIIJKQIBAAKCAgEAvbjpw9ZFgc8ZvCWCpGMCoCsDCNbRAsj5Sh0csCCeV4mswDMD
dDf7ObMeK7F/Rp4+TgUoWFeBHEzc5E2tE1akxqNglf4pdsyDhfKeYdJ0ByHiSCni
TGbEwz2RacjJ6gDMZZLHt9iGYpmFYnlOG5+RZLCEK9TABJrJwbtrNTs+izB+VqQs
dzh3XJ/u2U30+/rX3PImF9vMQKYKyJE2w5N0M5N44fXloPMgRpcUpFv4HhViRd7s
(... truncated 41 lines ...)
2R7RDfWXuZ0jwGv1W3pxFYMqnnnits0ltwbxBmvFw2su+TJWIIYBoXiHl4vihVK5
GtUw9sNoVCTKnA404W8lJxfOTtqQvk2imSBr5QgV34t4AnuSaB6sMfKeai35Y5Ha
srBoLatunmWKxgSU9OHz85Dmj+Vvb48zMT1jsw8luifDSZ7u3Y3eRmVTtpti9DAa
CVidWgYbN/hJrTdYJpdxSFmetosh6wTSXAdmk/XkaVAuzmKvfnsWEpf5eUz+
-----END RSA PRIVATE KEY-----
```

At this point each finding is ready to be reported across all supported output formats.
