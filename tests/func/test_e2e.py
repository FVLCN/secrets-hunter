import json
import re
import time
import unittest
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import patch

from secrets_hunter.models import Confidence


@dataclass
class KeyBlock:
    block_type: str
    begin_line: int
    end_line: int
    content: str


KEY_BLOCK_RE = re.compile(
    r"-----BEGIN (?P<type>[^-]+?)-----\s*"
    r"(?P<body>.*?)"
    r"-----END (?P=type)-----",
    re.DOTALL,
)

# Directory containing the test script
SCRIPT_DIR = Path(__file__).resolve().parent

# Test data configuration
secrets = str(SCRIPT_DIR / "secrets/secrets.txt")
mid_secrets = str(SCRIPT_DIR / "secrets/mid_secrets.txt")
no_assignment_secrets = str(SCRIPT_DIR / "secrets/no_assignment_secrets.txt")
rejected_secrets = str(SCRIPT_DIR / "secrets/rejected_secrets.txt")

valid_keys = str(SCRIPT_DIR / "keys/valid_keys.txt")
invalid_keys = str(SCRIPT_DIR / "keys/invalid_keys.txt")

# Module and report paths
MODULE = "secrets_hunter.cli"
report_json = str(SCRIPT_DIR / "results.json")
report_sarif = str(SCRIPT_DIR / "results.sarif")



class TestE2E(unittest.TestCase):
    """End-to-end tests for secrets hunter CLI"""

    def setUp(self):
        """Set up test environment before each test"""
        self._cleanup_reports()

    def tearDown(self):
        """Clean up test environment after each test"""
        self._cleanup_reports()

    def _get_key_block_lines(self):
        """
        Return all line numbers that belong to key blocks.
        These lines should not be checked as regular line findings.
        """
        key_block_lines = set()

        for block in self.key_blocks:
            key_block_lines.update(range(block.begin_line, block.end_line + 1))

        return key_block_lines

    def _get_key_block_start_lines(self):
        """
        Return lines where key block findings are expected.
        """
        return {block.begin_line for block in self.key_blocks}

    def _validate_mixed_line_numbers(self, findings, line_extractor):
        """
        Validate mixed scenario:
        - regular line findings are expected for all lines outside key blocks
        - key findings are expected only on key block start lines
        - lines inside key blocks must not appear as regular findings
        """
        all_lines = set(range(1, len(self.source_lines) + 1))

        key_block_lines = self._get_key_block_lines()
        key_start_lines = self._get_key_block_start_lines()

        expected_regular_lines = all_lines - key_block_lines
        expected_lines = expected_regular_lines | key_start_lines

        actual_lines = set()
        for finding in findings:
            try:
                actual_lines.add(line_extractor(finding))
            except (KeyError, IndexError, TypeError) as e:
                print(f"Warning: Could not extract line number from finding: {e}")

        missing_lines = expected_lines - actual_lines
        extra_lines = actual_lines - expected_lines

        error_messages = []

        if missing_lines:
            missing_key_lines = missing_lines & key_start_lines
            missing_regular_lines = missing_lines - key_start_lines

            if missing_key_lines:
                error_messages.append(
                    f"Missing key findings for block start lines: {sorted(missing_key_lines)}"
                )

                for block in self.key_blocks:
                    if block.begin_line in missing_key_lines:
                        error_messages.append(
                            f"Missed key block: {block.block_type} "
                            f"(lines {block.begin_line}-{block.end_line})"
                        )

            if missing_regular_lines:
                error_messages.append("\nContent of missing regular lines:")
                for line_num in sorted(missing_regular_lines):
                    content = self._get_line_content(line_num)
                    error_messages.append(f"Missed line || Line {line_num}: {content}")

        if extra_lines:
            error_messages.append(
                f"\nUnexpected lines in report: {sorted(extra_lines)} "
                f"(total: {len(extra_lines)})"
            )

            extra_key_block_lines = extra_lines & key_block_lines
            extra_key_block_lines = extra_key_block_lines - key_start_lines

            if extra_key_block_lines:
                error_messages.append(
                    f"Lines inside key blocks were parsed as regular lines: "
                    f"{sorted(extra_key_block_lines)}"
                )

        return error_messages

    def _load_source_lines(self, file_to_scan):
        """
        Load and cache lines from the source file being scanned.
        This allows us to show actual content of missing lines.
        """
        try:
            with open(file_to_scan, "r", encoding="utf-8") as f:
                self.source_lines = f.readlines()
            print(f"Loaded {len(self.source_lines)} lines from {file_to_scan}")
        except Exception as e:
            print(f"Warning: Could not load source file: {e}")
            self.source_lines = []

    def parse_key_blocks(self, text: str) -> list[KeyBlock]:
        blocks = []

        for match in KEY_BLOCK_RE.finditer(text):
            full_block = match.group(0)
            block_type = match.group("type").strip()

            start_pos = match.start()
            end_pos = match.end()

            begin_line = text.count("\n", 0, start_pos) + 1
            end_line = text.count("\n", 0, end_pos) + 1

            blocks.append(
                KeyBlock(
                    block_type=block_type,
                    begin_line=begin_line,
                    end_line=end_line,
                    content=full_block,
                )
            )

        return blocks

    def _load_key_blocks(self, file_to_scan):
        try:
            text = Path(file_to_scan).read_text(encoding="utf-8")
            self.key_blocks = self.parse_key_blocks(text)
            print(f"Parsed {len(self.key_blocks)} key blocks from {file_to_scan}")
        except Exception as e:
            print(f"Warning: Could not parse key blocks: {e}")
            self.key_blocks = []

    def _get_line_content(self, line_number):
        """
        Get content of a specific line from the source file.

        Args:
            line_number: Line number (1-indexed)

        Returns:
            String content of the line, or error message if not available
        """
        if not self.source_lines:
            return "<source file not loaded>"

        if 1 <= line_number <= len(self.source_lines):
            content = self.source_lines[line_number - 1].rstrip('\n')
            max_length = 100
            if len(content) > max_length:
                content = content[:max_length] + "..."
            return content
        else:
            return "<line number out of range>"

    def _cleanup_reports(self):
        """
        Fixture: Remove generated scan report files if they exist.
        This ensures a clean state before and after each test.
        """
        for report_path in [report_json, report_sarif]:
            path = Path(report_path)
            if path.exists():
                try:
                    path.unlink()
                    print(f"Cleaned up report: {report_path}")
                except Exception as e:
                    print(f"Warning: Could not delete {report_path}: {e}")

    def _check_confidence(self,
                          findings,
                          confidence_extractor,
                          line_extractor,
                          awaited_confidence,
                          ):
        error_messages = []
        for finding in findings:
            try:
                confidence = confidence_extractor(finding)
                confidence_result = confidence not in awaited_confidence if isinstance(awaited_confidence,
                                                                                       list) else confidence != awaited_confidence
                if confidence_result:
                    line_num = line_extractor(finding)

                    content = self._get_line_content(line_num)
                    error_messages.append(
                        f"Confidence {confidence} != awaited {awaited_confidence} || Line {line_num}: {content}")

            except (KeyError, IndexError, TypeError) as e:
                print(f"Warning: Could not extract line number from finding: {e}")

        return error_messages

    def run_main(self, argv):
        """
        Execute the secrets-hunter CLI with given arguments.

        Args:
            argv: List of command-line arguments

        Returns:
            Exit code from the CLI execution
        """
        print(f"Running command: secrets-hunter {' '.join(argv)}")
        with patch(f"{MODULE}.sys.argv", ["secrets-hunter"] + argv):
            with self.assertRaises(SystemExit) as cm:
                __import__(MODULE, fromlist=["main"]).main()
            return cm.exception.code

    def check_json(self, file_path, awaited_confidence, is_fail_on_findings=False,
                   min_confidence=Confidence.REJECTED):
        args = [file_path, "--json", report_json, "--min-confidence", str(min_confidence.value)]
        if is_fail_on_findings:
            args += ["--fail-on-findings"]

        code = self.run_main(args)
        self.assertTrue(
            code == (2 if is_fail_on_findings and awaited_confidence > min_confidence else 0),
            msg=f"Return code not equal to awaited: {code}, is_fail_on_findings={is_fail_on_findings}"
        )

        self._load_key_blocks(file_path)
        self._load_source_lines(file_path)


        time.sleep(0.1)

        self.assertTrue(
            Path(report_json).exists(),
            msg=f"JSON report was not created at {report_json}"
        )

        with open(report_json, "r", encoding="utf-8") as f:
            report = json.load(f)

            if awaited_confidence < min_confidence:
                self.assertTrue(
                    len(report) == 0,
                    msg=f"JSON report is not empty {report_json}"
                )
                return

            line_numbers_errors = self._validate_mixed_line_numbers(
                report,
                lambda finding: finding["line"],
            )

            confidence_error = self._check_confidence(
                report,
                lambda finding: finding["confidence"],
                lambda finding: finding["line"],
                awaited_confidence=awaited_confidence,
            )

            error_messages = line_numbers_errors + confidence_error
            if error_messages:
                self.assertFalse(
                    error_messages,
                    msg="\n".join(error_messages)
                )

    def check_sarif(self, file_path, awaited_confidence, is_fail_on_findings=False,
                    min_confidence=Confidence.REJECTED):
        args = [file_path, "--sarif", report_sarif, "--min-confidence", str(min_confidence.value)]
        if is_fail_on_findings:
            args += ["--fail-on-findings"]
        code = self.run_main(args)
        self.assertTrue(
            code == (2 if is_fail_on_findings and awaited_confidence > min_confidence else 0),
            msg=f"Return code not equal to awaited: {code}, is_fail_on_findings={is_fail_on_findings}"
        )
        self._load_key_blocks(file_path)
        self._load_source_lines(file_path)

        time.sleep(0.1)

        self.assertTrue(
            Path(report_sarif).exists(),
            msg=f"SARIF report was not created at {report_sarif}"
        )

        with open(report_sarif, "r", encoding="utf-8") as f:
            report = json.load(f)["runs"][0]["results"]
            if awaited_confidence < min_confidence:
                self.assertTrue(
                    len(report) == 0,
                    msg=f"SARIF report is not empty {report_sarif}"
                )
                return

            line_numbers_errors = self._validate_mixed_line_numbers(
                report,
                lambda finding: finding["locations"][0]["physicalLocation"]["region"]["startLine"],
            )

            confidence_error = self._check_confidence(
                report,
                lambda finding: finding["properties"]["confidence"],
                lambda finding: finding["locations"][0]["physicalLocation"]["region"]["startLine"],
                awaited_confidence=awaited_confidence,
            )

            error_messages = line_numbers_errors + confidence_error

            if error_messages:
                self.assertFalse(
                    error_messages,
                    msg="\n".join(error_messages) if error_messages else ""
                )

    def test_json_verified_confidence(self):
        self.check_json(secrets, Confidence.VERIFIED)

    def test_sarif_mid_confidence(self):
        self.check_sarif(mid_secrets, Confidence.HIGH_ENTROPY_WITH_ASSIGNMENT, is_fail_on_findings=True)

    def test_json_no_assignment_confidence(self):
        self.check_json(no_assignment_secrets, Confidence.HIGH_ENTROPY_NO_ASSIGNMENT_CONTEXT)

    def test_sarif_rejected_confidence(self):
        self.check_sarif(rejected_secrets, Confidence.REJECTED, is_fail_on_findings=True)

    def test_json_rejected_confidence(self):
        self.check_json(rejected_secrets, Confidence.REJECTED, is_fail_on_findings=True)

    def test_sarif_rejected_confidence_zero_findings(self):
        self.check_sarif(rejected_secrets, Confidence.REJECTED, is_fail_on_findings=True,
                         )

    def test_json_no_assignment_confidence_zero_findings(self):
        self.check_json(no_assignment_secrets, Confidence.HIGH_ENTROPY_NO_ASSIGNMENT_CONTEXT, is_fail_on_findings=True,
                        )

    def test_json_verified_confidence_keys(self):
        self.check_json(valid_keys, Confidence.VERIFIED, min_confidence=Confidence.VERIFIED)

    def test_sarif_rejected_confidence_keys(self):
        self.check_sarif(invalid_keys, Confidence.REJECTED)


if __name__ == '__main__':
    unittest.main()
