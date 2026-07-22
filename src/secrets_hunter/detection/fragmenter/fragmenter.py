import re

from collections.abc import Callable

from secrets_hunter.detection.pem import PEM_BEGIN_RE, analyze_pem_header
from secrets_hunter.detection.value_patterns import (
    CREDENTIAL_URI_RE,
    VALUE_BOUNDARY_CHARS
)
from secrets_hunter.detection.fragmenter.models import (
    LineFragment, GenericStringFragment, DBConnectionFragment, PEMKeyFragment, SourceFragment
)


_IDENTIFIER_RE = re.compile(
    r"^(?:[a-z][a-z0-9]*(?:_[a-z0-9]+)*|[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*|[a-z][a-zA-Z0-9]*)$"
)
_QUOTED_STRING_RE = re.compile(
    r'"((?:\\.|[^"\\]){5,})"|\'((?:\\.|[^\'\\]){5,})\'|`((?:\\.|[^`\\]){5,})`'
)


def _chunk_re(min_token_length: int) -> re.Pattern[str]:
    return re.compile(rf"\S{{{min_token_length},}}")


class SourceFragmenter:
    """
    Splits source text into candidate values for secret detection.
    """

    def __init__(
        self,
        min_token_length: int,
        is_high_entropy: Callable[[str], bool]
    ) -> None:
        self.min_token_length = min_token_length
        self.max_identifier_len = 40
        self.is_high_entropy = is_high_entropy
        self._chunk_re = _chunk_re(min_token_length)

    @staticmethod
    def _extract_and_blank[_FragmentT: LineFragment](
        line: str,
        pattern: re.Pattern[str],
        fragment_factory: Callable[[str], _FragmentT]
    ) -> tuple[str, list[_FragmentT]]:
        """Match all occurrences of pattern, collect as LineFragments, blank them out."""
        fragments: list[_FragmentT] = []

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
            pem_analysis = analyze_pem_header(header_match.group(0))

            if pem_analysis is None:
                raise ValueError(f"Unsupported PEM header: {header_match.group(0)!r}")

            expected_footer = pem_analysis.pem_type.footer_marker
            footer_start = content.find(expected_footer, header_match.end())

            if footer_start != -1:
                fragment_end = footer_start + len(expected_footer)
                fragment_content = content[header_match.start():fragment_end]
                body = content[header_match.end():footer_start].strip() or None
                footer = expected_footer
                blank_end = fragment_end
            else:
                fragment_content = header_match.group(0)
                body = None
                footer = None
                blank_end = len(content)

            fragments.append(PEMKeyFragment(
                content=fragment_content,
                body=body,
                footer=footer,
                pem_analysis=pem_analysis
            ))

            content = (
                content[:header_match.start()]
                + " " * (blank_end - header_match.start())
                + content[blank_end:]
            )

            header_match = PEM_BEGIN_RE.search(content)

        return content, fragments

    def _looks_like_identifier(self, s: str) -> bool:
        if not _IDENTIFIER_RE.match(s):
            return False

        if len(s) > self.max_identifier_len:
            return False

        return not self.is_high_entropy(s)

    def _split_assignment(self, s: str) -> str | None:
        """If it's key=value or key:value, keep only RHS (value) when it's long enough"""
        for sep in ("=", ":"):
            if sep in s:
                lhs, rhs = s.split(sep, 1)
                lhs = lhs.strip(VALUE_BOUNDARY_CHARS).lstrip("-")
                rhs = rhs.strip(VALUE_BOUNDARY_CHARS).lstrip("=")

                if self._looks_like_identifier(lhs):
                    return rhs if len(rhs) >= self.min_token_length else ""

        return None

    def extract(self, source_fragment: SourceFragment) -> list[LineFragment]:
        fragments: list[LineFragment] = []

        # PEM headers, DB URIs
        line, pem = self._extract_pem_and_blank(source_fragment)
        fragments.extend(pem)
        line, db_conn = self._extract_and_blank(
            line,
            CREDENTIAL_URI_RE,
            DBConnectionFragment
        )
        fragments.extend(db_conn)

        # 1) collect quoted strings + blank them out
        line_wo_quotes = line
        for m in _QUOTED_STRING_RE.finditer(line):
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
            cleaned = chunk.strip(VALUE_BOUNDARY_CHARS)

            result = self._split_assignment(cleaned)

            if result:
                fragments.append(GenericStringFragment(result))
            elif result is None and len(cleaned) >= self.min_token_length:
                fragments.append(GenericStringFragment(cleaned))

        seen: set[str] = set()
        unique_strings: list[LineFragment] = []

        for f in fragments:
            if f.content not in seen:
                seen.add(f.content)
                unique_strings.append(f)

        return unique_strings
