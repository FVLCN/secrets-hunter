import re

from secrets_hunter.config.patterns import EXCLUDE_PATTERNS


class FalsePositiveValidator:
    @staticmethod
    def is_valid(string: str) -> bool:
        """Check if string matches common false positive patterns"""
        string_lower = string.lower()

        for pattern in EXCLUDE_PATTERNS:
            if re.search(pattern, string_lower):
                return False

        return True


class MinLengthValidator:
    def __init__(self, min_string_length):
        self.min_string_length = min_string_length

    def is_valid(self, string: str) -> bool:
        return len(string) >= self.min_string_length
