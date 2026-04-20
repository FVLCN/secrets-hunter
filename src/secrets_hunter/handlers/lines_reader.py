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

        for line_num, line in iterator:
            header_match = PEM_BEGIN_RE.search(line)

            if not header_match:
                yield SourceFragment(
                    content=line,
                    start_line=line_num,
                    end_line=line_num,
                )
                continue

            block_lines = [line]
            start_line = line_num
            end_line = line_num
            pem_type = header_match.group(1)
            expected_footer = f"-----END {pem_type}-----"

            if expected_footer in line:
                yield SourceFragment(
                    content="".join(block_lines),
                    start_line=start_line,
                    end_line=end_line,
                )
                continue

            for skipped_line_num, skipped_line in iterator:
                block_lines.append(skipped_line)
                end_line = skipped_line_num

                if expected_footer in skipped_line:
                    break

            yield SourceFragment(
                content="".join(block_lines),
                start_line=start_line,
                end_line=end_line,
            )
