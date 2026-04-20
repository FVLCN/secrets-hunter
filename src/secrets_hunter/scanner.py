import logging
import time

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from secrets_hunter.config import CLIArgs, STRIP
from secrets_hunter.detectors.entropy_detector import EntropyDetector
from secrets_hunter.detectors.pattern_detector import PatternDetector
from secrets_hunter.validators import FalsePositiveFindingsValidator
from secrets_hunter.handlers.progress_bar import FileProgressBar, FolderProgressBar
from secrets_hunter.semantics import StringSemanticsClassifier
from secrets_hunter.models import Finding, Severity, DetectionMethod, Confidence, SourceFragment
from secrets_hunter.models.config import RuntimeConfig
from secrets_hunter.handlers import (
    FileHandler, LineFragmenter, FindingsProcessor, PEMAwareLinesReader
)

logger = logging.getLogger(__name__)


class SecretsHunter:
    def __init__(self,  runtime_cfg: RuntimeConfig, cli_args: CLIArgs = None):
        self.cli_args = cli_args or CLIArgs()
        self.runtime_cfg = runtime_cfg
        self.pattern_detector = PatternDetector(self.runtime_cfg.secret_patterns)
        self.entropy_detector = EntropyDetector(self.cli_args)
        self.lines_reader = PEMAwareLinesReader()
        self.file_handler = FileHandler(
            set(self.runtime_cfg.ignore_files),
            set(self.runtime_cfg.ignore_extensions),
            set(self.runtime_cfg.ignore_dirs)
        )
        self.false_positive_validator = FalsePositiveFindingsValidator(
            exclude_patterns=self.runtime_cfg.exclude_patterns,
            exclude_keywords=self.runtime_cfg.exclude_keywords,
            string_semantics_classifier=StringSemanticsClassifier()
        )
        self.lines_fragmenter = LineFragmenter(
            assignment_patterns=self.runtime_cfg.assignment_patterns,
            min_token_length=self.cli_args.min_string_length,
            entropy_detector=self.entropy_detector
        )

    def is_secret_var(self, v: str) -> tuple[bool, str]:
        v = v.lower()

        for k in self.runtime_cfg.secret_keywords:
            if k in v:
                return True, k

        return False, ""

    def extract_findings_from_fragment(self, source_fragment: SourceFragment, filepath: Path) -> list[Finding]:
        fragment_line = source_fragment.start_line
        fragment_content = source_fragment.content

        # Step 1: Extract all strings from a source fragment
        all_fragments = self.lines_fragmenter.extract(source_fragment)

        if not all_fragments:
            return []

        # Step 2: Find high entropy strings
        entropy_findings = self.entropy_detector.detect(
            fragment_content, fragment_line, str(filepath), all_fragments
        )

        # Step 3: Find pattern matching strings
        pattern_findings = self.pattern_detector.detect(
            fragment_content, fragment_line, str(filepath), all_fragments
        )

        # Step 3.5: prioritize pattern findings (dedupe by match)
        pattern_matches = {f.match for f in pattern_findings if f.match}

        all_fragment_findings = list(pattern_findings)

        for ef in entropy_findings:
            if ef.match and ef.match not in pattern_matches:
                all_fragment_findings.append(ef)

        if not all_fragment_findings:
            return []

        # Step 4: Check and process the assignment context
        assignment_context = self.lines_fragmenter.assignment_map(fragment_content)
        transformed_findings = self._process_assignment_context(all_fragment_findings, assignment_context)

        return transformed_findings

    def _process_assignment_context(self, findings: list[Finding], ctx: dict) -> list[Finding]:
        transformed_findings: list[Finding] = []

        for finding in findings:
            finding_value_rejected, rejected_by = (
                self.false_positive_validator.check_rejection_for_finding_value(finding)
            )
            match = finding.match
            norm_match = match.strip().strip(STRIP)
            vars_ = ctx.get(match) or ctx.get(norm_match)

            if not vars_:
                if finding_value_rejected:
                    finding = finding.reject(f"{rejected_by.name} {rejected_by.category} in value")

                transformed_findings.append(finding)
                continue

            # can be multiple keys for a single secret,
            # pick the best var for display / single field
            vars_ordered = sorted(vars_)
            best = next((v for v in vars_ordered if self.is_secret_var(v)[0]), vars_ordered[0])

            reasoning = finding.confidence_reasoning
            severity = finding.severity
            confidence = finding.confidence

            if finding.detection_method == DetectionMethod.ENTROPY:
                reasoning = "High Entropy with assignment context"
                severity = Severity.MEDIUM
                confidence = Confidence.HIGH_ENTROPY_WITH_ASSIGNMENT

            finding = finding.with_context(
                var=best,
                severity=severity,
                confidence=confidence,
                reasoning=reasoning
            )

            kw_rejected, kw_rejected_by = self.false_positive_validator.check_rejection_for_keywords(vars_ordered)

            if kw_rejected:
                finding = finding.reject(kw_rejected_by + " in keyword/variable")
                transformed_findings.append(finding)
                continue

            is_secret, kw = self.is_secret_var(best)

            if finding_value_rejected:
                secret_hash = is_secret and rejected_by.category == "hash"

                if not secret_hash:
                    reasoning = f"{rejected_by.name} {rejected_by.category} in value"
                    transformed_findings.append(finding.reject(reasoning))
                    continue

            if is_secret:
                if finding.detection_method == DetectionMethod.ENTROPY:
                    reasoning = f"High Entropy in context of secret key/variable assignment - {kw}"
                    severity = Severity.CRITICAL
                    confidence = Confidence.VERIFIED

                finding = finding.with_context(
                    var=best,
                    severity=severity,
                    confidence=confidence,
                    reasoning=reasoning
                )

                transformed_findings.append(finding)
                continue

            transformed_findings.append(finding)

        return transformed_findings

    def scan_file(self, filepath: Path, show_progress: bool = False) -> tuple[list[Finding], bool]:
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
                for source_fragment in self.lines_reader.read(lines, filepath):
                    fragment_findings = self.extract_findings_from_fragment(source_fragment, filepath)
                    findings.extend(fragment_findings)
                    last_line_number = source_fragment.end_line

                    if progress_bar and (
                        source_fragment.end_line % progress_bar.STEP == 0 or source_fragment.start_line == 1
                    ):
                        progress_bar.render(source_fragment.end_line)

                if progress_bar and last_line_number:
                    progress_bar.render(last_line_number)

                success = True

        except Exception as e:
            logger.error(f"Error scanning file {filepath}: {e}", exc_info=True)

        if show_progress:
            success_msg = "finished" if success else "failed"
            print("")
            logger.info(f"Scan {success_msg}.")

        return findings, success

    def scan_directory(self, directory: str) -> tuple[list[Finding], bool]:
        all_findings: list[Finding] = []
        success: bool = False
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
        logger.info(f"Scanning with {self.cli_args.max_workers} workers...\n")

        processed_count = 0
        failed_count = 0
        progress_bar = FolderProgressBar()

        try:
            with ThreadPoolExecutor(max_workers=self.cli_args.max_workers) as executor:
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
            print("\n")

            if failed_count:
                logger.warning(f"Scan finished with {failed_count} file(s) skipped.")
            else:
                logger.info("Scan finished.")

        except KeyboardInterrupt:
            print("\n")
            logger.info("Scan aborted.")
            return all_findings, False

        return all_findings, success

    def scan(self, target: str) -> tuple[list[Finding], bool]:
        """Scan target (file or directory)"""
        findings: list[Finding] = []
        success: bool = False
        target_path = Path(target)

        if target_path.is_file() or target_path.is_dir():
            self.pattern_detector.set_base_path(target)
            self.entropy_detector.set_base_path(target)

        start_time = time.monotonic()

        if target_path.is_file():
            findings, success = self.scan_file(target_path, show_progress=True)
        elif target_path.is_dir():
            findings, success = self.scan_directory(target)
        else:
            logger.error(f"'{target}' is not a valid file or directory")
            return findings, success

        elapsed = time.monotonic() - start_time
        minutes =  int(elapsed // 60)
        seconds = int(elapsed % 60)
        milliseconds = int((elapsed % 1) * 1000)
        duration = f"{minutes}m {seconds}s {milliseconds}ms" if minutes else f"{seconds}s {milliseconds}ms"
        logger.info(f"Scan duration: {duration}")

        if success:
            if not self.cli_args.min_confidence:
                logger.info("Showing all findings, including rejected ones. "
                            "To exclude them from the report, use --min-confidence argument")

            findings = FindingsProcessor.process(findings, self.cli_args)

        return findings, success
