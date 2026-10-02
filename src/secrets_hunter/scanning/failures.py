import traceback

from secrets_hunter.models import ScanFailure, ScanFailureKind


class OperationalScanError(RuntimeError):
    """An expected source or environment failure during scanning."""


def source_scan_failure(label: str, message: str) -> ScanFailure:
    return ScanFailure(
        label=label,
        message=message,
        kind=ScanFailureKind.SOURCE
    )


def scan_failure_from_exception(
    label: str,
    error: Exception
) -> ScanFailure:
    message = str(error).strip() or repr(error)

    if isinstance(error, OperationalScanError):
        return source_scan_failure(label, message)

    return ScanFailure(
        label=label,
        message=message,
        kind=ScanFailureKind.INTERNAL,
        exception_type=type(error).__name__,
        diagnostic="".join(traceback.format_exception(
            type(error),
            error,
            error.__traceback__
        ))
    )
