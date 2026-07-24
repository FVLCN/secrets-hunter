from secrets_hunter.config import ScanOptions
from secrets_hunter.detection.assignment_resolver import AssignmentResolver
from secrets_hunter.detection.candidate_assessor import CandidateAssessor
from secrets_hunter.detection.detectors.entropy_detector import EntropyDetector
from secrets_hunter.detection.detectors.pattern_detector import PatternDetector
from secrets_hunter.detection.engine import DetectionEngine
from secrets_hunter.detection.entropy_classification import EntropyClassifier
from secrets_hunter.detection.fragmenter.fragmenter import SourceFragmenter
from secrets_hunter.detection.fragmenter.lines_reader import PEMAwareLinesReader
from secrets_hunter.detection.rejection_analyzer import CandidateRejectionAnalyzer
from secrets_hunter.detection.value_analysis import ValueAnalyzer
from secrets_hunter.runtime import ApplicationRuntime
from secrets_hunter.scanning.cancellation import ScanCancellation
from secrets_hunter.scanning.content_safety import (
    DEFAULT_CONTENT_SAFETY_POLICY
)
from secrets_hunter.scanning.content_validator import TextContentValidator
from secrets_hunter.scanning.control import ScanControl
from secrets_hunter.scanning.executor import ScanExecutor
from secrets_hunter.scanning.modes import ScannerContext
from secrets_hunter.scanning.path_filter import PathFilter
from secrets_hunter.scanning.progress import (
    IsolatedScanProgressObserver,
    NullScanProgressObserver,
    ScanProgressObserver
)
from secrets_hunter.scanning.session import ScanSession
from secrets_hunter.scanning.source_scanner import SourceScanner
from secrets_hunter.scanning.text_reader import SourceTextReader


def compose_scan_session(
    runtime: ApplicationRuntime,
    options: ScanOptions,
    *,
    cancellation: ScanCancellation | None = None,
    progress: ScanProgressObserver | None = None
) -> ScanSession:
    observer = (
        progress
        if progress is not None
        else NullScanProgressObserver()
    )
    scan_progress = IsolatedScanProgressObserver(observer)
    scan_cancellation = (
        cancellation
        if cancellation is not None
        else ScanCancellation()
    )
    control = ScanControl(
        cancellation=scan_cancellation,
        progress=scan_progress
    )
    runtime_config = runtime.config
    entropy_classifier = EntropyClassifier(
        runtime.value_classifier,
        hex_threshold=options.hex_entropy_threshold,
        b64_threshold=options.b64_entropy_threshold
    )
    detection_engine = DetectionEngine(
        pattern_detector=PatternDetector(runtime.pattern_plan),
        entropy_detector=EntropyDetector(entropy_classifier),
        source_fragmenter=SourceFragmenter(
            min_token_length=options.min_string_length,
            is_high_entropy=entropy_classifier.is_high_entropy
        ),
        assignment_resolver=AssignmentResolver(
            runtime_config.compiled_assignment_patterns
        ),
        candidate_assessor=CandidateAssessor(
            rejection_analyzer=CandidateRejectionAnalyzer(
                rejection_patterns=runtime_config.rejection_patterns
            ),
            semantic_runtime=runtime.semantics,
            value_analyzer=ValueAnalyzer(runtime.value_classifier)
        )
    )
    source_scanner = SourceScanner(
        detection_engine,
        PEMAwareLinesReader(),
        control
    )
    executor = ScanExecutor(
        options.max_workers,
        control
    )
    return ScanSession(
        options=options,
        control=control,
        executor=executor,
        source_scanner=source_scanner
    )


def compose_path_filter(runtime: ApplicationRuntime) -> PathFilter:
    runtime_config = runtime.config
    return PathFilter(
        set(runtime_config.ignore_files),
        set(runtime_config.ignore_extensions),
        set(runtime_config.ignore_dirs)
    )


def compose_scanner_context(
    runtime: ApplicationRuntime,
    options: ScanOptions,
    *,
    cancellation: ScanCancellation | None = None,
    progress: ScanProgressObserver | None = None
) -> ScannerContext:
    content_safety = DEFAULT_CONTENT_SAFETY_POLICY
    return ScannerContext(
        session=compose_scan_session(
            runtime,
            options,
            cancellation=cancellation,
            progress=progress
        ),
        content_validator=TextContentValidator(content_safety),
        source_text_reader=SourceTextReader(content_safety),
        path_filter=compose_path_filter(runtime)
    )
