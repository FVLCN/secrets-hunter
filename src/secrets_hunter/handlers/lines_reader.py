from collections import deque
from typing import Iterable
from pathlib import Path

from secrets_hunter.config import PEM_BEGIN_RE
from secrets_hunter.models import SourceFragment


class LinesReader:
    def read(self, lines: Iterable[str], filepath: Path):
        for line_num, line in enumerate(lines, 1):
            yield SourceFragment(
                content=line,
                start_line=line_num,
                end_line=line_num,
            )


class PEMAwareLinesReader(LinesReader):
    def read(self, lines: Iterable[str], filepath: Path):
        iterator = enumerate(lines, 1)
        pending: deque[tuple[int, str]] = deque()

        def next_item() -> tuple[int, str] | None:
            if pending:
                return pending.popleft()

            return next(iterator, None)

        def make_fragment(fragment_lines: list[tuple[int, str]]) -> SourceFragment:
            return SourceFragment(
                content="".join(text for _, text in fragment_lines),
                start_line=fragment_lines[0][0],
                end_line=fragment_lines[-1][0],
            )

        def replay(items: list[tuple[int, str]]) -> None:
            for item in reversed(items):
                pending.appendleft(item)

        while True:
            current_item = next_item()

            if current_item is None:
                break

            current_line_num, current_line = current_item
            header_match = PEM_BEGIN_RE.search(current_line)

            if not header_match:
                yield SourceFragment(
                    content=current_line,
                    start_line=current_line_num,
                    end_line=current_line_num,
                )
                continue

            pem_candidate = [(current_line_num, current_line)]
            pem_type = header_match.group(1)
            expected_footer = f"-----END {pem_type}-----"

            if expected_footer in current_line:
                yield make_fragment(pem_candidate)
                continue

            while True:
                lookahead_item = next_item()

                if lookahead_item is None:
                    yield make_fragment(pem_candidate)
                    replay(pem_candidate[1:])
                    break

                lookahead_line_num, lookahead_line = lookahead_item

                if PEM_BEGIN_RE.search(lookahead_line):
                    yield make_fragment(pem_candidate)
                    replay(pem_candidate[1:] + [(lookahead_line_num, lookahead_line)])
                    break

                if expected_footer in lookahead_line:
                    pem_candidate.append((lookahead_line_num, lookahead_line))
                    yield make_fragment(pem_candidate)
                    break

                pem_candidate.append((lookahead_line_num, lookahead_line))
