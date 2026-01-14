import logging

from pathlib import Path
from typing import List, Set, Iterator
from secrets_hunter.config.settings import MAX_LINE_LENGTH, MAX_REPEAT_RUN

logger = logging.getLogger(__name__)


class FileHandler:
    """Handle file operations for scanning"""
    
    def __init__(self, ignore_extensions: Set[str], ignore_dirs: Set[str]):
        self.ignore_extensions = {ext.lower() for ext in ignore_extensions}
        self.ignore_dirs = ignore_dirs

    @staticmethod
    def is_text_file(path: Path) -> bool:
        try:
            with open(path, 'rb') as f:
                chunk = f.read(2048)

            # Empty file is considered text
            if not chunk:
                return True

            # NULL byte indicates binary file
            if b'\x00' in chunk:
                return False

            # Calculate ratio of printable characters
            printable_chars = sum(
                32 <= byte <= 126 or byte in (ord('\n'), ord('\r'), ord('\t'))
                for byte in chunk
            )

            # Too many non-printable chars = binary
            text_ratio = printable_chars / len(chunk)
            return text_ratio > 0.85
        except OSError:
            return False

    def should_skip(self, path: Path) -> bool:
        if path.is_dir():
            return path.name in self.ignore_dirs

        return (not self.is_text_file(path) or
                path.suffix.lower() in self.ignore_extensions)

    @staticmethod
    def read_file(filepath: Path) -> Iterator[str]:
        try:
            with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    if len(line) > MAX_LINE_LENGTH:
                        return

                    run = 1
                    for i in range(1, len(line)):
                        if line[i] == line[i - 1]:
                            run += 1
                            if run >= MAX_REPEAT_RUN:
                                return
                        else:
                            run = 1

                    yield line

        except (OSError, UnicodeDecodeError) as e:
            print("\n")
            logger.error(f"Error reading {filepath}: {e}")

    def get_files_to_scan(self, target_path: Path) -> List[Path]:
        if target_path.is_file():
            return [target_path] if not self.should_skip(target_path) else []

        files = []
        dirs_to_process = [target_path]

        while dirs_to_process:
            current_dir = dirs_to_process.pop()

            try:
                for item in current_dir.iterdir():
                    if item.is_dir():
                        if item.name not in self.ignore_dirs:
                            dirs_to_process.append(item)
                    elif not self.should_skip(item):
                        files.append(item)
            except (PermissionError, OSError):
                pass

        return files
