import logging

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Tuple

from secrets_hunter.config import patterns, settings
from secrets_hunter.detectors.entropy_detector import EntropyDetector
from secrets_hunter.detectors.pattern_detector import PatternDetector
from secrets_hunter.detectors.utils import StringsExtractor, validators
from secrets_hunter.handlers.file_handler import FileHandler
from secrets_hunter.handlers.progress import FileProgressBar, FolderProgressBar
from secrets_hunter.models import Finding

logger = logging.getLogger(__name__)


class SecretsHunter:
    def __init__(self, config: settings.ScannerConfig = None):
        self.config = config or settings.ScannerConfig()
        self.pattern_detector = PatternDetector(self.config)
        self.entropy_detector = EntropyDetector(self.config)
        self.file_handler = FileHandler(
            settings.IGNORE_EXTENSIONS,
            settings.IGNORE_DIRS
        )
        self.validators = [
            validators.FalsePositiveValidator(),
            validators.MinLengthValidator(min_string_length=self.config.MIN_STRING_LENGTH)
        ]
        self.strings_extractor = StringsExtractor()

    def is_string_valid(self, string: str) -> bool:
        return all(validator.is_valid(string) for validator in self.validators)

    @staticmethod
    def is_secret_var(v: str) -> bool:
        v = v.lower()
        return any(k in v for k in patterns.SECRET_KEYWORDS)

    def extract_findings_from_line(self, line_num: int, line: str, filepath: Path) -> List[Finding]:
        # Step 1: Extract all strings from a line
        all_strings = self.strings_extractor.extract(line)

        if not all_strings:
            return []

        # Step 2: Filter using validators
        filtered_strings = [
            string for string in all_strings if self.is_string_valid(string)
        ]

        if not filtered_strings:
            return []

        # Step 3: Find high entropy strings
        entropy_findings = self.entropy_detector.detect(
            line, line_num, str(filepath), filtered_strings
        )

        # Step 4: Find pattern matching strings
        pattern_findings = self.pattern_detector.detect(
            line, line_num, str(filepath), filtered_strings
        )

        all_line_findings = pattern_findings + entropy_findings

        # Step 5: Check if in assignment for better confidence
        ctx = self.strings_extractor.assignment_map(line)

        for finding in all_line_findings:
            key = finding.match

            if not key:
                continue

            vars_ = ctx.get(key)

            if not vars_:
                continue

            # can be multiple vars in a single line,
            # pick the best var for display / single field
            ordered = sorted(vars_)
            best = next((v for v in ordered if self.is_secret_var(v)), ordered[0])

            finding.context_var = best

            if self.is_secret_var(best):
                finding.confidence = 100

        return all_line_findings

    def scan_file(self, filepath: Path, show_progress: bool = False) -> Tuple[List[Finding], bool]:
        findings, success = [], False
        progress_bar = None
        last_line_number = 0

        if show_progress:
            logger.info(f"Scanning {filepath}...")
            progress_bar = FileProgressBar()

        try:
            lines = self.file_handler.read_file(filepath)

            if lines is None:
                logger.error(f"Failed to read file: {filepath}")
            else:
                for line_num, line in enumerate(lines, 1):
                    line_findings = self.extract_findings_from_line(line_num, line, filepath)
                    findings.extend(line_findings)
                    last_line_number = line_num

                    if show_progress and progress_bar and (line_num % 100 == 0 or line_num == 1):
                        progress_bar.render(line_num)

                if show_progress and progress_bar and last_line_number:
                    progress_bar.render(last_line_number)

                success = True

        except Exception as e:
            logger.error(f"Error scanning file {filepath}: {e}", exc_info=True)

        if show_progress:
            success_msg = "finished" if success else "failed"
            print("")
            logger.info(f"Scan {success_msg}.")

        return findings, success

    def scan_directory(self, directory: str) -> Tuple[List[Finding], bool]:
        all_findings, success = [], False
        target_path = Path(directory)

        if not target_path.exists():
            logger.error(f"Error: Path '{directory}' does not exist")
            return all_findings, success

        display_path = Path.cwd() if directory == "." else directory
        logger.info(f"Collecting files from {display_path}...")
        files = self.file_handler.get_files_to_scan(target_path)
        total_files = len(files)

        if not files:
            logger.warning("No files to scan")
            return all_findings, True

        logger.info(f"Found {total_files} files to scan")
        logger.info(f"Scanning with {self.config.MAX_WORKERS} workers...\n")

        processed_count = 0
        failed_count = 0
        progress_bar = FolderProgressBar()

        try:
            with ThreadPoolExecutor(max_workers=self.config.MAX_WORKERS) as executor:
                futures = {executor.submit(self.scan_file, f, show_progress=False): f for f in files}

                for future in as_completed(futures):
                    filepath = futures[future]

                    try:
                        file_findings, file_success = future.result()

                        if not file_success:
                            failed_count += 1
                            print("\n")
                            logger.error(f"Error scanning file {filepath}, skipping...")
                            continue

                        all_findings.extend(file_findings)
                    except Exception as e:
                        failed_count += 1
                        print("\n")
                        logger.error(f"Error scanning file {filepath}: {e}, skipping...", exc_info=True)
                        continue
                    finally:
                        processed_count += 1
                        progress_bar.render(processed_count, total_files)

            success = True

            if failed_count:
                logger.warning(f"Scan finished with {failed_count} file(s) skipped.")
            else:
                logger.info("Scan finished.")

            print("\n")

        except KeyboardInterrupt:
            print("\n")
            logger.info("Scan aborted.")
            return all_findings, False

        return all_findings, success

    def scan(self, target: str) -> Tuple[List[Finding], bool]:
        """Scan target (file or directory)"""
        findings, success = [], False
        target_path = Path(target)

        if target_path.is_file():
            findings, success = self.scan_file(target_path, show_progress=True)
        elif target_path.is_dir():
            findings, success = self.scan_directory(target)
        else:
            logger.error(f"'{target}' is not a valid file or directory")

        if success:
            findings.sort(key=lambda f: f.confidence, reverse=True)

        return findings, success
