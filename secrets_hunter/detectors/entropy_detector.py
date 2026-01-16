from typing import List
from secrets_hunter.detectors.base import BaseDetector
from secrets_hunter.models import Finding
from secrets_hunter.detectors.utils import entropy as entropy_utils


class EntropyDetector(BaseDetector):
    """Detect secrets using entropy analysis"""

    def detect(self, line: str, line_num: int, filepath: str, strings: List[str]) -> List[Finding]:
        findings = []

        for string in strings:
            entropy = entropy_utils.calculate_shannon_entropy(string)
            is_hex = entropy_utils.is_hex_string(string)
            is_base64 = entropy_utils.is_base64_string(string)

            is_high_entropy = False
            string_type = None

            if is_hex and entropy >= self.config.HEX_ENTROPY_THRESHOLD:
                is_high_entropy = True
                string_type = "High Entropy Hex String"
            elif is_base64 and entropy >= self.config.B64_ENTROPY_THRESHOLD:
                is_high_entropy = True
                string_type = "High Entropy Base64 String"

            if is_high_entropy:
                findings.append(Finding(
                    file=filepath,
                    line=line_num,
                    type=string_type,
                    match=string,
                    context=line.strip()[:100],
                    detection_method='entropy',
                    confidence=50
                ))

        return findings
