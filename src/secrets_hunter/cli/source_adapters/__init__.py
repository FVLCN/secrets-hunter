from . import domain, filesystem, git_history
from ..protocols import ScanSourceAdapter


SCAN_SOURCE_ADAPTERS: tuple[ScanSourceAdapter, ...] = (
    filesystem,
    git_history,
    domain
)

__all__ = ["SCAN_SOURCE_ADAPTERS"]
