import logging
import re

from pathlib import Path
from typing import List, Tuple, Optional
from threading import Event
from concurrent.futures import ThreadPoolExecutor, as_completed
from secrets_hunter.config import settings, patterns
from secrets_hunter.detectors.pattern_detector import PatternDetector
from secrets_hunter.detectors.entropy_detector import EntropyDetector
from secrets_hunter.handlers.file_handler import FileHandler
from secrets_hunter.handlers.progress import ProgressBar
from secrets_hunter.detectors.utils import validators
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

    @staticmethod
    def extract_all_strings(line: str) -> List[str]:
        """Extract all potential strings from a line"""
        strings = []

        # Extract complete multi-line PEM keys
        pem_pattern = r'-----BEGIN[^-]+-----.*?-----END[^-]+-----'
        pem_matches = re.findall(pem_pattern, line, re.DOTALL)
        strings.extend(pem_matches)

        # Extract quoted strings
        quote_patterns = [
            r'"([^"]{4,})"',  # At least 4 chars to avoid noise
            r"'([^']{4,})'",
        ]

        for pattern in quote_patterns:
            matches = re.findall(pattern, line)
            # Filter out matches that are part of already-captured PEM keys
            for match in matches:
                if not any(match in pem for pem in pem_matches):
                    strings.append(match)

        # Extract unquoted tokens that look like secrets (alphanumeric sequences)
        token_pattern = r'\b([A-Za-z0-9_\-]{8,})\b'  # At least 8 chars
        token_matches = re.findall(token_pattern, line)

        # Filter out tokens that are part of PEM keys
        for token in token_matches:
            if not any(token in existing for existing in pem_matches + strings):
                strings.append(token)

        # Remove duplicates while preserving order
        seen = set()
        unique_strings = []
        for s in strings:
            if s not in seen:
                seen.add(s)
                unique_strings.append(s)

        return unique_strings

    @staticmethod
    def find_assignment_context(line: str, string: str) -> Optional[str]:
        """Find if this string is part of an assignment and return variable name"""
        for pattern in patterns.ASSIGNMENT_PATTERNS:
            matches = re.finditer(pattern, line)

            for match in matches:
                variable = match.group(1).lower()
                value = match.group(2).strip('\'"')

                if string in value:
                    return variable

        return None

    def is_string_valid(self, string):
        return all(validator.is_valid(string) for validator in self.validators)

    def scan_file(self, filepath: Path) -> Tuple[List[Finding], bool]:
        findings, success = [], False
        lines = self.file_handler.read_file(filepath)

        for line_num, line in enumerate(lines, 1):
            # Step 1: Extract ALL strings from line
            all_strings = self.extract_all_strings(line)

            if not all_strings:
                continue

            # Step 2: Filter using validators
            filtered_strings = [string for string in all_strings if self.is_string_valid(string)]

            if not filtered_strings:
                continue

            # Step 3: Find high entropy strings
            entropy_findings = self.entropy_detector.detect(line, line_num, str(filepath), filtered_strings)

            # Step 4: Find pattern matching strings
            pattern_findings = self.pattern_detector.detect(line, line_num, str(filepath), filtered_strings)

            # Combine all findings
            all_line_findings = pattern_findings + entropy_findings

            # Step 5: Check if in assignment for better confidence
            for finding in all_line_findings:
                match_string = finding.match.replace('...', '') if finding.match else ''

                if match_string:
                    context_var = self.find_assignment_context(line, match_string)

                    if context_var:
                        finding.context_var = context_var

                        if any(keyword in context_var for keyword in patterns.SECRET_KEYWORDS):
                            finding.confidence = 100

            findings.extend(all_line_findings)

        success = True
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
            return all_findings, success

        logger.info(f"Found {total_files} files to scan")
        logger.info(f"Scanning with {self.config.MAX_WORKERS} workers...\n")

        completed = 0
        stop_scanning = Event()
        progress_bar = ProgressBar()

        try:
            with ThreadPoolExecutor(max_workers=self.config.MAX_WORKERS) as executor:
                futures = {executor.submit(self.scan_file, f): f for f in files}

                for future in as_completed(futures):
                    if stop_scanning.is_set():
                        raise KeyboardInterrupt

                    filepath = futures[future]

                    try:
                        file_findings, file_success = future.result()

                        if not file_success:
                            logger.error(f"Error scanning file {filepath}, aborting...")
                            raise KeyboardInterrupt

                        all_findings.extend(file_findings)
                    except Exception as e:
                        logger.error(f"Error scanning file {filepath}: {e}, aborting...", exc_info=True)
                        raise KeyboardInterrupt

                    completed += 1
                    progress_bar.render(completed, total_files)

            success = True
            print("\n")
            logger.info("Scan finished.")

        except KeyboardInterrupt:
            stop_scanning.set()
            print("\n")
            logger.info("Scan aborted.")
            return all_findings, success

        all_findings.sort(key=lambda f: f.confidence, reverse=True)
        return all_findings, success

    def scan(self, target: str) -> Tuple[List[Finding], bool]:
        """Scan target (file or directory)"""
        findings, success = [], False
        target_path = Path(target)

        if target_path.is_file():
            return self.scan_file(target_path)
        elif target_path.is_dir():
            return self.scan_directory(target)
        else:
            logger.error(f"'{target}' is not a valid file or directory")
            return findings, success
