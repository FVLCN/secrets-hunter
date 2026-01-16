import re

from typing import List
from secrets_hunter.detectors.base import BaseDetector
from secrets_hunter.config.patterns import SECRET_PATTERNS
from secrets_hunter.models import Finding


class PatternDetector(BaseDetector):
    """Detects secrets using regex patterns"""

    def detect(self, line: str, line_num: int, filepath: str, strings: List[str]) -> List[Finding]:
        findings = []

        for string in strings:
            for secret_type, pattern in SECRET_PATTERNS.items():
                if re.search(pattern, string):
                    findings.append(Finding(
                        file=filepath,
                        line=line_num,
                        type=secret_type,
                        match=string,
                        context=line.strip()[:100],
                        detection_method='pattern',
                        confidence=100
                    ))

        return findings
