DEFAULT_ASSIGNMENT_PATTERN_SOURCES = (
    # Assignment operators: a = "secret" or "a" = "secret" or key => "value" or key =: "value" etc.
    r'''["']?([a-zA-Z_][a-zA-Z0-9_]*)["']?\s*(?:==|=|:=|=>|=:)\s*["'`]([^"'`]+)["'`]''',
    # Colon key-value pairs: a: "secret" or "a": "secret" (JSON, YAML)
    r'''["']?([a-zA-Z_][a-zA-Z0-9_]*)["']?\s*:\s*["']([^"']+)["']''',
    # token = abc123def456xyz789 (unquoted)
    r'''["']?([a-zA-Z_][a-zA-Z0-9_]*)["']?\s*[:=]\s*([^\s,}]+)''',
    # Tuple/function assignments: (password, "secret") or ("user", 'pass') or ('key', "value")
    r'''\(\s*["']?([^"',\s()]+)["']?\s*,\s*["']([^"']+)["']\s*\)?''',
    # Docker ENV statements: ENV API_KEY "secret123" or ENV PASSWORD secret
    r'''ENV\s+([A-Z_][A-Z0-9_]*)\s+["']?([^"'\n]+)["']?''',
    # C/C++ preprocessor defines: #define API_KEY "secret123"
    r'''#define\s+([A-Z_][A-Z0-9_]*)\s+["']([^"']+)["']''',
    # Python with type hints: api_key: str | None = "secret123"
    r'''([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*[^=\n]+\s*=\s*["']([^"']+)["']'''
)
