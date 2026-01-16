import re

# Regex patterns for known secret formats
SECRET_PATTERNS = {
    "AWS Access Key": r"\bAKIA[0-9A-Z]{16}\b",
    "GitHub Token": r"\bgh[pousr]_[A-Za-z0-9]{36,}\b",
    "Private Key": r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
    "JWT Token": r"\beyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\b",
    "Slack Token": r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b",
    "Google API Key": r"\bAIza[0-9A-Za-z_-]{35}\b",
    "Stripe API Key": r"\bsk_live_[0-9a-zA-Z]{24,}\b",
    "Twilio API Key": r"\bSK[0-9a-fA-F]{32}\b",
    "SendGrid API Key": r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b",
    "Mailchimp API Key": r"\b[0-9a-f]{32}-us[0-9]{1,2}\b",
    "NPM Token": r"\bnpm_[A-Za-z0-9]{36}\b",
    "PyPI Token": r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b",
    "Docker Hub Token": r"\bdckr_pat_[A-Za-z0-9_-]{40}\b",
    "Database URL": r"(?i)(?:postgresql|mysql|mongodb|redis)://[^\s]+:[^\s]+@[^\s]+",
}

# False positive patterns
EXCLUDE_PATTERNS = [
    r'^[0-9a-f]{32}$',  # MD5 hashes
    r'^[0-9a-f]{40}$',  # SHA1 hashes
    r'^[0-9a-f]{64}$',  # SHA256 hashes
    r'^[0-9a-f]{128}$',  # SHA512 hashes
    r'^[0-9a-f]{56}$',  # SHA224 hashes
    r'^[0-9a-f]{96}$',  # SHA384 hashes
    r'^[A-Za-z0-9+/]{27}=$',  # Base64 encoded MD5
    r'^[A-Za-z0-9+/]{43}=$',  # Base64 encoded SHA256
    r'^\$2[ayb]\$.{56}$',  # Bcrypt hashes
    r'^\$argon2id?\$',  # Argon2 hashes
    r'^[0-9]+:[0-9a-f]+:[0-9a-f]+$',  # PBKDF2 format
    r'test', r'example', r'sample',
    r'demo', r'placeholder', r'12345',
    r'abcde', r'aaaaa', r'xxxxx',
    r'dummy', r'fake', r'mock',
    r'testpass', r'blob'
]

# Keywords that suggest secrets
SECRET_KEYWORDS = [
    'secret', 'token', 'api_key', 'apikey',
    'credential', 'auth', 'password', 'passwd',
    'pwd', 'private', 'key'
]

# Patterns to detect variable assignments that might contain secrets
ASSIGNMENT_PATTERNS_RAW = [
    # API_KEY = "abc123def456" or password: "secret123"
    r'([a-zA-Z_][a-zA-Z0-9_]*)\s*[:=]\s*["\']([^"\']+)["\']',

    # token = abc123def456xyz789 (unquoted, 20+ chars)
    r'([a-zA-Z_][a-zA-Z0-9_]*)\s*[:=]\s*([a-zA-Z0-9+/=_\-]{20,})',

    # const apiKey = `sk_test_abc123` (JavaScript template literals)
    r'([a-zA-Z_][a-zA-Z0-9_]*)\s*[:=]\s*`([^`]+)`',

    # export API_KEY="abc123" (shell scripts)
    r'export\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*[:=]\s*["\']([^"\']+)["\']',

    # set PASSWORD="secret123" (Windows batch/PowerShell)
    r'set\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*[:=]\s*["\']([^"\']+)["\']',

    # const SECRET_KEY = "abc123" (JavaScript/TypeScript)
    r'const\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*[:=]\s*["\']([^"\']+)["\']',

    # let authToken = "bearer_xyz" (JavaScript/TypeScript)
    r'let\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*[:=]\s*["\']([^"\']+)["\']',

    # var password = "secret" (JavaScript)
    r'var\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*[:=]\s*["\']([^"\']+)["\']',

    # define('DB_PASSWORD', 'secret123'); (PHP constants)
    r'define\s*\(\s*["\']([^"\']+)["\']\s*,\s*["\']([^"\']+)["\']',

    # $api_key = "abc123"; (PHP/Perl variables)
    r'\$([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*["\']([^"\']+)["\']',
]

ASSIGNMENT_PATTERNS = [re.compile(p) for p in ASSIGNMENT_PATTERNS_RAW]
