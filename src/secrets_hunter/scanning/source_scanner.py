from collections import deque
from collections.abc import Callable, Iterable, Iterator

from secrets_hunter.detection.engine import DetectionEngine
from secrets_hunter.detection.fragmenter.lines_reader import PEMAwareLinesReader
from secrets_hunter.detection.fragmenter.models import SourceContext, SourceFragment
from secrets_hunter.detection.value_context import MAX_CONTEXT_BYTES, MAX_CONTEXT_LINES
from secrets_hunter.models import Finding, ScanFailure, ScanResult, ScanSkip
from secrets_hunter.scanning.control import ScanControl
from secrets_hunter.scanning.failures import source_scan_failure
from secrets_hunter.scanning.source_identity import SourceIdentity
from secrets_hunter.scanning.text_reader import SourceReadLimitError


class SourceScanner:
    def __init__(
        self,
        detection_engine: DetectionEngine,
        lines_reader: PEMAwareLinesReader,
        control: ScanControl
    ) -> None:
        self.detection_engine = detection_engine
        self.lines_reader = lines_reader
        self.control = control

    def _fragments_with_context(
        self,
        lines: Iterable[str]
    ) -> Iterator[tuple[SourceFragment, Callable[[], SourceContext | None]]]:
        fragments = iter(self.lines_reader.read(lines))
        history: deque[tuple[SourceFragment, int]] = deque()
        pending: deque[tuple[SourceFragment, int]] = deque()
        history_bytes = 0
        pending_bytes = 0
        error: SourceReadLimitError | OSError | None = None
        exhausted = False
        previous_limit = (MAX_CONTEXT_LINES - 1) // 2
        following_limit = MAX_CONTEXT_LINES - previous_limit - 1

        def eligible(fragment: SourceFragment, size: int) -> bool:
            return fragment.start_line == fragment.end_line and size <= MAX_CONTEXT_BYTES

        def pull() -> bool:
            nonlocal error, exhausted, pending_bytes
            if exhausted or self.control.cancellation.cancelled:
                return False
            try:
                fragment = next(fragments)
            except StopIteration:
                exhausted = True
                return False
            except (SourceReadLimitError, OSError) as exc:
                error = exc
                exhausted = True
                return False
            size = len(fragment.content.encode("utf-8"))
            if not fragment.content.endswith(("\n", "\r")):
                size += 1
            pending.append((fragment, size))
            pending_bytes += size
            return True

        def get_context() -> SourceContext | None:
            # The engine resolves this while the generator is paused at yield.
            if not eligible(current, size):
                return current.source_context
            before = list(history)
            after: list[tuple[SourceFragment, int]] = []
            for item in pending:
                if not eligible(*item):
                    break
                after.append(item)
            total = size + history_bytes + sum(n for _, n in after)
            while total > MAX_CONTEXT_BYTES:
                removed = before.pop(0) if len(before) > len(after) else after.pop()
                total -= removed[1]
            window = [fragment for fragment, _ in before] + [current] + [fragment for fragment, _ in after]
            return SourceContext(
                content="".join(
                    fragment.content if fragment.content.endswith(("\n", "\r"))
                    else fragment.content + "\n"
                    for fragment in window
                ),
                start_line=window[0].start_line
            )

        while pending or not exhausted:
            if self.control.cancellation.cancelled:
                return
            if not pending and not pull():
                break

            current, size = pending[0]
            if eligible(current, size):
                while (
                    len(pending) <= following_limit
                    and pending_bytes < MAX_CONTEXT_BYTES
                    and eligible(*pending[-1])
                ):
                    if not pull():
                        break

            pending.popleft()
            pending_bytes -= size
            yield current, get_context
            if eligible(current, size):
                history.append((current, size))
                history_bytes += size
                while len(history) > previous_limit or history_bytes > MAX_CONTEXT_BYTES:
                    history_bytes -= history.popleft()[1]
            else:
                history.clear()
                history_bytes = 0

        if error is not None:
            raise error

    def scan(
        self,
        lines: Iterable[str] | None,
        source: SourceIdentity
    ) -> ScanResult:
        findings: list[Finding] = []
        display_label = source.display_label
        self.control.progress.source_started(display_label)

        if lines is None:
            return ScanResult(
                total_items=1,
                attempted_items=1,
                failures=(
                    ScanFailure(
                        label=display_label,
                        message="Failed to read source"
                    ),
                )
            )

        try:
            for source_fragment, context_provider in self._fragments_with_context(lines):
                if self.control.cancellation.cancelled:
                    return ScanResult(
                        findings=tuple(findings),
                        total_items=1,
                        attempted_items=1,
                        aborted=True
                    )

                findings.extend(
                    self.detection_engine.scan_fragment(
                        source_fragment,
                        source.location,
                        context_provider=context_provider
                    )
                )
                self.control.progress.source_progress(
                    display_label,
                    source_fragment.end_line
                )
        except SourceReadLimitError as error:
            return ScanResult(
                findings=tuple(findings),
                total_items=1,
                attempted_items=1,
                skips=(ScanSkip(label=display_label, message=str(error)),),
            )
        except OSError as error:
            return ScanResult(
                findings=tuple(findings),
                total_items=1,
                attempted_items=1,
                failures=(
                    source_scan_failure(display_label, str(error)),
                )
            )

        if self.control.cancellation.cancelled:
            return ScanResult(
                findings=tuple(findings),
                total_items=1,
                attempted_items=1,
                aborted=True
            )

        return ScanResult(
            findings=tuple(findings),
            total_items=1,
            attempted_items=1,
            successful_items=1
        )
