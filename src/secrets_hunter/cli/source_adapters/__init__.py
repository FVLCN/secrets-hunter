from secrets_hunter.scanning.modes import ScanModeRegistry

from . import domain, filesystem, git_history
from ..protocols import ScanSourceAdapter


SCAN_SOURCE_ADAPTERS: tuple[ScanSourceAdapter, ...] = (
    filesystem,
    git_history,
    domain
)

CLI_SOURCE_ADAPTERS: dict[str, ScanSourceAdapter] = {
    name: adapter
    for adapter in SCAN_SOURCE_ADAPTERS
    for name in adapter.NAMES
}

CLI_SCAN_MODE_REGISTRY = ScanModeRegistry(
    adapter.SCAN_MODE
    for adapter in SCAN_SOURCE_ADAPTERS
)

__all__ = [
    "CLI_SCAN_MODE_REGISTRY",
    "CLI_SOURCE_ADAPTERS",
    "SCAN_SOURCE_ADAPTERS"
]
