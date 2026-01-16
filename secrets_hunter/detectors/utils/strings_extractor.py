import re

from typing import List

from secrets_hunter.config.patterns import ASSIGNMENT_PATTERNS


class StringsExtractor:
    @staticmethod
    def assignment_map(line: str) -> dict[str, set[str]]:
        out: dict[str, set[str]] = {}
        for pattern in ASSIGNMENT_PATTERNS:
            for match in pattern.finditer(line):
                var = match.group(1).lower()
                val = match.group(2).strip().strip("'\"")
                out.setdefault(val, set()).add(var)
        return out

    @staticmethod
    def extract(line: str) -> List[str]:
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
