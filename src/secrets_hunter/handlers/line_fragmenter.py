import re

from secrets_hunter.config import STRIP, PEM_BEGIN_RE, DB_URI_RE
from secrets_hunter.models.line_fragment import (
    LineFragment, GenericStringFragment, DBConnectionFragment, PEMKeyFragment, SourceFragment
)


class LineFragmenter:
    """
    Extracts candidate secret fragments from a SourceFragment.
    """

    def __init__(self, assignment_patterns, min_token_length, entropy_detector):
        self.assignment_patterns = assignment_patterns
        self.min_token_length = min_token_length
        self.max_identifier_len = 40
        self.entropy_detector = entropy_detector

        # snake_case, SCREAMING_SNAKE, camelCase
        self._identifier_re = re.compile(
            r'^(?:[a-z][a-z0-9]*(?:_[a-z0-9]+)*|[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*|[a-z][a-zA-Z0-9]*)$'
        )

        # quoted strings (handles escapes)
        self._quoted_re = re.compile(r'"((?:\\.|[^"\\]){5,})"|\'((?:\\.|[^\'\\]){5,})\'|`((?:\\.|[^`\\]){5,})`')

        # any non-whitespace chunk with length >= min_token_length
        self._chunk_re = re.compile(rf'\S{{{min_token_length},}}')

    def assignment_map(self, line: str) -> dict[str, set[str]]:
        out: dict[str, set[str]] = {}

        for pattern in self.assignment_patterns:
            for match in pattern.finditer(line):
                var = match.group(1).lower()
                val = match.group(2).strip().strip(STRIP)
                out.setdefault(val, set()).add(var)

                for sep in ("=", ":"):
                    if sep in val:
                        rhs = val.split(sep, 1)[1].strip(STRIP).lstrip("=")
                        if rhs != val and len(rhs) > 0:
                            out.setdefault(rhs, set()).add(var)
                        break

        return out

    @staticmethod
    def _extract_and_blank(
        line: str,
        pattern,
        fragment_factory
    ) -> tuple[str, list[LineFragment]]:
        """Match all occurrences of pattern, collect as LineFragments, blank them out."""
        fragments = []

        for m in pattern.finditer(line):
            fragments.append(fragment_factory(m.group(0)))
            start, end = m.span()
            line = line[:start] + " " * (end - start) + line[end:]

        return line, fragments

    @staticmethod
    def _extract_pem_and_blank(source_fragment: SourceFragment) -> tuple[str, list[PEMKeyFragment]]:
        content = source_fragment.content
        fragments: list[PEMKeyFragment] = []
        header_match = PEM_BEGIN_RE.search(content)

        while header_match is not None:
            pem_type = header_match.group(1)
            expected_footer = f"-----END {pem_type}-----"
            footer_start = content.find(expected_footer, header_match.end())

            fragment_end = footer_start + len(expected_footer) if footer_start != -1 else len(content)
            fragment_content = content[header_match.start():fragment_end]
            body = content[header_match.end():footer_start if footer_start != -1 else fragment_end].strip() or None
            footer = expected_footer if footer_start != -1 else None

            fragments.append(PEMKeyFragment(
                content=fragment_content,
                header=header_match.group(0),
                body=body,
                footer=footer,
                inline=source_fragment.start_line == source_fragment.end_line,
            ))

            content = (
                content[:header_match.start()]
                + " " * (fragment_end - header_match.start())
                + content[fragment_end:]
            )

            header_match = PEM_BEGIN_RE.search(content)

        return content, fragments

    def _looks_like_identifier(self, s: str) -> bool:
        if not self._identifier_re.match(s):
            return False

        if len(s) > self.max_identifier_len:
            return False

        # high entropy - likely not an identifier but a token chunk
        findings = self.entropy_detector.detect("", 0, "", [GenericStringFragment(s)])

        return len(findings) == 0

    def _split_assignment(self, s: str) -> str | None:
        """If it's key=value or key:value, keep only RHS (value) when it's long enough"""
        for sep in ("=", ":"):
            if sep in s:
                lhs, rhs = s.split(sep, 1)
                lhs = lhs.strip(STRIP).lstrip("-")
                rhs = rhs.strip(STRIP).lstrip("=")

                if self._looks_like_identifier(lhs):
                    return rhs if len(rhs) >= self.min_token_length else ""

        return None

    def extract(self, source_fragment: SourceFragment) -> list[LineFragment]:
        fragments = []

        # PEM headers, DB URIs
        line, pem = self._extract_pem_and_blank(source_fragment)
        fragments.extend(pem)
        line, db_conn = self._extract_and_blank(line, DB_URI_RE, DBConnectionFragment)
        fragments.extend(db_conn)

        # 1) collect quoted strings + blank them out
        line_wo_quotes = line
        for m in self._quoted_re.finditer(line):
            s = m.group(1) or m.group(2) or m.group(3)

            if s:
                result = self._split_assignment(s)

                if result:
                    fragments.append(GenericStringFragment(result))
                elif result is None:
                    fragments.append(GenericStringFragment(s))

            # remove whole quoted span to avoid extracting them twice
            start, end = m.span()
            line_wo_quotes = line_wo_quotes[:start] + " " * (end - start) + line_wo_quotes[end:]

        # 2) collect other long chunks (unquoted)
        for chunk in self._chunk_re.findall(line_wo_quotes):
            cleaned = chunk.strip(STRIP)

            result = self._split_assignment(cleaned)

            if result:
                fragments.append(GenericStringFragment(result))
            elif result is None and len(cleaned) >= self.min_token_length:
                fragments.append(GenericStringFragment(cleaned))

        seen = set()
        unique_strings = []

        for f in fragments:
            if f.content not in seen:
                seen.add(f.content)
                unique_strings.append(f)

        return unique_strings
