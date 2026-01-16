HEX_ENTROPY_MAX = 4.5
B64_ENTROPY_MAX = 6.0
MAX_LINE_LENGTH = 50000
MAX_REPEAT_RUN = 1000
MAX_WORKERS_MULTIPLIER = 2


class ScannerConfig:
    HEX_ENTROPY_THRESHOLD = 3.0
    B64_ENTROPY_THRESHOLD = 4.5
    MIN_STRING_LENGTH = 10
    MAX_WORKERS = 4
    LOG_LEVEL = "INFO"


IGNORE_EXTENSIONS = {
    ".exe", ".dll", ".so", ".dylib",
    ".zip", ".tar", ".gz", ".bz2", ".xz",
    ".7z", ".rar",
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg",
    ".mp4", ".mov", ".avi", ".mkv",
    ".pdf",
    ".woff", ".woff2", ".ttf", ".otf",
    ".class", ".o", ".a",
    ".db", ".sqlite",
    ".bin", ".img", ".iso"
}

IGNORE_DIRS = {
    'node_modules', '.git', 'venv', '__pycache__',
    'dist', 'build', '.venv', 'env', '.tox', '.idea'
}
