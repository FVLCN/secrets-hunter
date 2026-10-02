from threading import Event


class ScanCancelledError(RuntimeError):
    """Internal control flow raised when blocking scan work is cancelled."""


class ScanCancellation:
    def __init__(self) -> None:
        self._event = Event()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    def cancel(self) -> None:
        self._event.set()
