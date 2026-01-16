import math
import sys


class FolderProgressBar:
    def __init__(self, bar_width: int = 40):
        self.bar_width = bar_width

    def render(self, done: int, total_files: int):
        ratio = done / total_files
        filled = math.floor(self.bar_width * ratio)
        bar = "█" * filled + "-" * (self.bar_width - filled)
        percent = int(ratio * 100)
        sys.stdout.write(
            f"\r[{bar}] {percent:3d}% ({done}/{total_files})"
        )
        sys.stdout.flush()


class FileProgressBar:
    @staticmethod
    def render(current_line: int):
        sys.stdout.write(
            f"\rCurrent progress: scanning line #{current_line}..."
        )
        sys.stdout.flush()
