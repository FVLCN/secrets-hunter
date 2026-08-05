from collections.abc import Iterable, Iterator

from secrets_hunter.scanning.content_safety import ContentSafetyPolicy
from secrets_hunter.scanning.failures import OperationalScanError


class SourceReadLimitError(OperationalScanError):
    """Raised when source content exceeds a configured scanning safety limit."""


class SourceTextReader:
    def __init__(self, policy: ContentSafetyPolicy) -> None:
        self.policy = policy

    def bytes_to_lines(self, content: bytes) -> Iterator[str]:
        text = content.decode("utf-8", errors="replace")
        return self.text_to_lines(text)

    def text_to_lines(self, content: str) -> Iterator[str]:
        return self.safe_lines(content.splitlines(keepends=True))

    def safe_lines(self, lines: Iterable[str]) -> Iterator[str]:
        for line_number, line in enumerate(lines, 1):
            if len(line) > self.policy.max_line_length:
                raise SourceReadLimitError(
                    f"Line {line_number} exceeds the maximum supported length "
                    f"of {self.policy.max_line_length} characters"
                )

            run = 1
            for index in range(1, len(line)):
                if line[index] == line[index - 1]:
                    run += 1
                    if run >= self.policy.max_repeat_run:
                        raise SourceReadLimitError(
                            f"Line {line_number} contains a repeated-character "
                            f"run of at least {self.policy.max_repeat_run} "
                            f"characters"
                        )
                else:
                    run = 1

            yield line
