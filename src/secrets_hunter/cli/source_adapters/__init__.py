from secrets_hunter.scanning.modes import ScanModeRegistry

from . import domain, filesystem, git_history
from ..protocols import ScanSourceAdapter


SCAN_SOURCE_ADAPTERS: tuple[ScanSourceAdapter, ...] = (
    filesystem,
    git_history,
    domain
)

CLI_SCAN_MODE_REGISTRY = ScanModeRegistry(
    adapter.SCAN_MODE
    for adapter in SCAN_SOURCE_ADAPTERS
)

__all__ = [
    "CLI_SCAN_MODE_REGISTRY",
    "SCAN_SOURCE_ADAPTERS"
]
