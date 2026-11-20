import re


COMMIT_ID_RE = re.compile(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\Z")
COMMIT_URL_REFERENCE_PATTERN = (
    r"https?://(?:github\.com|gitlab\.com|bitbucket\.org)/[^\s'\x22\x60]+/commits?/{value}\b"
)
ACTION_COMMIT_PIN_PATTERN = (
    r"(?m)^\s*(?:#\s*)?(?:-\s*)?uses\s*:\s*[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@{value}\b"
)
ACTION_COMMENT_COMMIT_PATTERN = (
    r"(?m)^\s*#\s*-\s+[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@\S+\s+\({value}\)"
)
ACTION_REFERENCE_RE = re.compile(
    r"\s*(?:-\s*)?uses:\s*(?P<action>[^\s#]+)@(?P<pin>[a-fA-F0-9]{40})"
    r"\s*(?:#(?P<comment>[^\n]*))?\s*"
)
ACTION_COMMIT_SHA_RE = re.compile(r"[a-fA-F0-9]{40}")
COMMENT_VALUE_REFERENCE_PATTERN = r"(?<!\w){value}(?!\w)"
GPG_KEY_ID_RE = re.compile(r"(?:0x)?(?:[0-9a-fA-F]{8}|[0-9a-fA-F]{16}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})!?\Z")
GIT_DIFF_HUNK_RE = re.compile(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
GIT_COMMIT_SHA_RE = re.compile(r"\A(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
