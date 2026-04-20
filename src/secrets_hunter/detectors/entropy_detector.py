import re

from secrets_hunter.detectors.base import BaseDetector
from secrets_hunter.config import CLIArgs
from secrets_hunter.models import (
    Finding, DetectionMethod, Severity, Confidence, LineFragment
)

from .utils import entropy as entropy_utils


class EntropyDetector(BaseDetector):
    """Detect secrets using entropy analysis"""

    def __init__(self, cli_args: CLIArgs):
        super().__init__()
        self.cli_args = cli_args
        self.ignore_prefixes = re.compile(r'^(?:sha\d+|md5)[-:]', re.IGNORECASE)

    def detect(
        self,
        line: str,
        line_num: int,
        filepath: str,
        fragments: list[LineFragment]
    ) -> list[Finding]:
        findings = []

        for fragment in fragments:
            cleaned = self.ignore_prefixes.sub('', fragment.content)

            entropy = entropy_utils.calculate_shannon_entropy(cleaned)
            is_hex = entropy_utils.is_hex_string(cleaned)
            is_base64 = entropy_utils.is_base64_string(cleaned)
            is_base64url = entropy_utils.is_base64url_string(cleaned)

            is_high_entropy = False
            string_type = None

            if is_hex and entropy >= self.cli_args.hex_entropy_threshold:
                is_high_entropy = True
                string_type = "High Entropy Hex String"
            elif (is_base64 or is_base64url) and entropy >= self.cli_args.b64_entropy_threshold:
                is_high_entropy = True
                string_type = "High Entropy Base64 String"

            if not is_high_entropy:
                continue

            file = self.format_filepath(filepath)

            findings.append(Finding(
                title=f"Hardcoded {string_type} at {file}:{line_num}",
                file=file,
                line=line_num,
                severity=Severity.LOW,
                type=string_type,
                fragment=fragment,
                match=fragment.content,
                context=line.strip()[:100],
                detection_method=DetectionMethod.ENTROPY,
                confidence=Confidence.HIGH_ENTROPY_NO_ASSIGNMENT_CONTEXT,
                confidence_reasoning="High Entropy without assignment context"
            ))

        return findings
