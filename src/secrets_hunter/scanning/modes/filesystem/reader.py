from collections.abc import Iterator
from pathlib import Path

from secrets_hunter.scanning.text_reader import SourceTextReader


class FileReader:
    def __init__(self, source_text_reader: SourceTextReader) -> None:
        self.source_text_reader = source_text_reader

    def read_file(self, filepath: Path) -> Iterator[str]:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            yield from self.source_text_reader.safe_lines(f)
