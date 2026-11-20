from .domain.mode import DOMAIN_MODE
from .filesystem.mode import FILESYSTEM_MODE
from .git_history.mode import GIT_HISTORY_MODE
from .registry import ScanModeRegistry
from .text.mode import TEXT_MODE


BUILTIN_SCAN_MODE_REGISTRY = ScanModeRegistry((
    TEXT_MODE,
    FILESYSTEM_MODE,
    GIT_HISTORY_MODE,
    DOMAIN_MODE
))
