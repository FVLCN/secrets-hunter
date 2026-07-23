from concurrent.futures import (
    FIRST_COMPLETED,
    Future,
    ThreadPoolExecutor,
    wait
)
from dataclasses import dataclass, field

from secrets_hunter.models import Finding, ScanFailure, ScanResult
from secrets_hunter.scanning.cancellation import ScanCancelledError
from secrets_hunter.scanning.control import ScanControl
from secrets_hunter.scanning.failures import scan_failure_from_exception
from secrets_hunter.scanning.work import ScanWorkItem, ScanWorkPlan


@dataclass
class _ExecutionState:
    findings: list[Finding] = field(default_factory=list)
    failures: list[ScanFailure] = field(default_factory=list)
    discovered_items: int = 0
    attempted_items: int = 0
    successful_items: int = 0
    processed_items: int = 0
    discovery_complete: bool = False

    def discover_item(self) -> None:
        self.discovered_items += 1

    def record_failure(self, failure: ScanFailure) -> None:
        self.discovered_items += 1
        self.attempted_items += 1
        self.processed_items += 1
        self.failures.append(failure)

    def record_result(self, result: ScanResult) -> None:
        self.findings.extend(result.findings)
        self.attempted_items += result.attempted_items
        self.successful_items += result.successful_items
        self.failures.extend(result.failures)
        self.processed_items += 1

    def total_items(self, plan: ScanWorkPlan) -> int | None:
        if plan.total_items is not None:
            return plan.total_items

        if self.discovery_complete:
            return self.discovered_items

        return None

    def result(
        self,
        plan: ScanWorkPlan,
        *,
        aborted: bool = False
    ) -> ScanResult:
        return ScanResult(
            findings=tuple(self.findings),
            total_items=self.total_items(plan),
            attempted_items=self.attempted_items,
            successful_items=self.successful_items,
            failures=tuple(self.failures),
            aborted=aborted
        )


class ScanExecutor:
    PENDING_WORK_MULTIPLIER = 2

    def __init__(
        self,
        max_workers: int,
        control: ScanControl
    ) -> None:
        self.max_workers = max_workers
        self.control = control

    def execute(self, plan: ScanWorkPlan) -> ScanResult:
        if plan.total_items == 1:
            return self._execute_inline(plan)

        return self._execute_concurrently(plan)

    def _execute_inline(self, plan: ScanWorkPlan) -> ScanResult:
        state = _ExecutionState()
        aborted = False

        try:
            for event in plan.events:
                if self.control.cancellation.cancelled:
                    aborted = True
                    break

                if isinstance(event, ScanFailure):
                    state.record_failure(event)
                    continue

                state.discover_item()
                item_result = self._execute_item(event)
                state.record_result(item_result)

                if item_result.aborted:
                    aborted = True
                    break
            else:
                state.discovery_complete = True
        except (KeyboardInterrupt, ScanCancelledError):
            aborted = True
        except Exception as error:
            state.record_failure(
                scan_failure_from_exception(plan.label, error)
            )
            state.discovery_complete = True

        if aborted:
            self.control.cancellation.cancel()

        return state.result(plan, aborted=aborted)

    def _execute_item(self, item: ScanWorkItem) -> ScanResult:
        if self.control.cancellation.cancelled:
            return ScanResult(
                total_items=1,
                aborted=True
            )

        try:
            return item.run()
        except ScanCancelledError:
            return ScanResult(
                total_items=1,
                attempted_items=1,
                aborted=True
            )
        except Exception as error:
            return ScanResult(
                total_items=1,
                attempted_items=1,
                failures=(
                    scan_failure_from_exception(item.label, error),
                )
            )

    def _execute_concurrently(self, plan: ScanWorkPlan) -> ScanResult:
        state = _ExecutionState()
        events = iter(plan.events)
        pending_limit = self.max_workers * self.PENDING_WORK_MULTIPLIER
        executor = ThreadPoolExecutor(max_workers=self.max_workers)
        in_flight: set[Future[ScanResult]] = set()
        aborted = False

        try:
            while in_flight or not state.discovery_complete:
                while (
                    not state.discovery_complete
                    and len(in_flight) < pending_limit
                ):
                    if self.control.cancellation.cancelled:
                        aborted = True
                        break

                    try:
                        event = next(events)
                    except StopIteration:
                        state.discovery_complete = True
                        if state.processed_items:
                            self._notify_progress(state, plan)
                        break
                    except ScanCancelledError:
                        aborted = True
                        break
                    except Exception as error:
                        state.record_failure(
                            scan_failure_from_exception(plan.label, error)
                        )
                        state.discovery_complete = True
                        self._notify_progress(state, plan)
                        break

                    if isinstance(event, ScanFailure):
                        state.record_failure(event)
                        self._notify_progress(state, plan)
                        continue

                    state.discover_item()
                    in_flight.add(
                        executor.submit(self._execute_item, event)
                    )

                if aborted:
                    break

                if not in_flight:
                    continue

                completed, _ = wait(
                    in_flight,
                    return_when=FIRST_COMPLETED
                )
                in_flight.difference_update(completed)

                for future in completed:
                    item_result = future.result()
                    state.record_result(item_result)

                    if item_result.aborted:
                        aborted = True
                        break

                    self._notify_progress(state, plan)

                if aborted:
                    break
        except KeyboardInterrupt:
            aborted = True
        except BaseException:
            self.control.cancellation.cancel()
            executor.shutdown(wait=True, cancel_futures=True)
            raise

        if aborted:
            self.control.cancellation.cancel()

        executor.shutdown(
            wait=True,
            cancel_futures=aborted
        )
        return state.result(plan, aborted=aborted)

    def _notify_progress(
        self,
        state: _ExecutionState,
        plan: ScanWorkPlan
    ) -> None:
        self.control.progress.item_completed(
            state.processed_items,
            state.total_items(plan)
        )
