from abc import ABC, abstractmethod

from secrets_hunter.models import ScanResult
from secrets_hunter.scanning.cancellation import ScanCancelledError
from secrets_hunter.scanning.failures import scan_failure_from_exception
from secrets_hunter.scanning.session import ScanSession
from secrets_hunter.scanning.work import ScanWorkPlan


class BaseScanner(ABC):
    def __init__(self, session: ScanSession) -> None:
        self.session = session

    @abstractmethod
    def create_work_plan(self) -> ScanWorkPlan:
        pass

    def scan(self) -> ScanResult:
        control = self.session.control

        try:
            plan = self.create_work_plan()
            control.progress.scan_started(
                plan.total_items,
                self.session.options.max_workers,
                single_source=plan.total_items == 1
            )
            result = self.session.executor.execute(plan)
        except (KeyboardInterrupt, ScanCancelledError):
            control.cancellation.cancel()
            result = ScanResult(aborted=True)
        except Exception as error:
            result = ScanResult(
                total_items=1,
                attempted_items=1,
                failures=(
                    scan_failure_from_exception(type(self).__name__, error),
                )
            )

        control.progress.scan_completed(result)
        return result
