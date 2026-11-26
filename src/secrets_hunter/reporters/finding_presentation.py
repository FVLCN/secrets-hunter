from collections.abc import Iterable
from dataclasses import replace

from secrets_hunter.config import FindingPresentationOptions
from secrets_hunter.config.validation import FindingPresentationOptionsValidator
from secrets_hunter.detection.pem import PEM_BEGIN_RE, PEM_END_RE
from secrets_hunter.models import Finding
from secrets_hunter.reporters.finding_view import FindingView

PEM_HEAD_LINES = 4
PEM_TAIL_LINES = 4
GENERIC_HEAD_CHARS = 80
GENERIC_TAIL_CHARS = 80
MASKED_VALUE = "***MASKED***"


def truncate_pem_match(match_text: str) -> str | None:
    lines = match_text.splitlines()

    if len(lines) < 3:
        return None

    header_match = PEM_BEGIN_RE.fullmatch(lines[0])
    footer_match = PEM_END_RE.fullmatch(lines[-1])

    if not header_match or not footer_match:
        return None

    if header_match.group(1) != footer_match.group(1):
        return None

    body_lines = lines[1:-1]
    kept_lines = PEM_HEAD_LINES + PEM_TAIL_LINES

    if len(body_lines) <= kept_lines:
        return match_text

    truncated_count = len(body_lines) - kept_lines
    replacement_lines = [
        lines[0],
        *body_lines[:PEM_HEAD_LINES],
        f"(... truncated {truncated_count} lines ...)",
        *body_lines[-PEM_TAIL_LINES:],
        lines[-1]
    ]

    return "\n".join(replacement_lines)


def truncate_generic_match(match_text: str) -> str:
    kept_chars = GENERIC_HEAD_CHARS + GENERIC_TAIL_CHARS

    if len(match_text) <= kept_chars:
        return match_text

    truncated_count = len(match_text) - kept_chars
    match_truncated = (
        match_text[:GENERIC_HEAD_CHARS]
        + f"(... truncated {truncated_count} chars ...)"
        + match_text[-GENERIC_TAIL_CHARS:]
    )

    return match_truncated


def truncate_match(match_text: str) -> str:
    pem_result = truncate_pem_match(match_text)

    if pem_result is not None:
        return pem_result

    return truncate_generic_match(match_text)


def present_findings(
    findings: Iterable[Finding],
    options: FindingPresentationOptions
) -> list[FindingView]:
    """Create output views without changing which findings were selected."""
    FindingPresentationOptionsValidator.validate(options)
    finding_views: list[FindingView] = []

    for finding in findings:
        match = finding.match
        context = finding.context

        if options.truncate_long_matches:
            match = truncate_match(match)

        if not options.reveal_findings:
            match = MASKED_VALUE
            context = MASKED_VALUE

        view = FindingView.from_finding(
            finding,
            match=match,
            context=context
        )
        analysis = view.semantic_analysis
        if not options.reveal_findings and analysis is not None:
            masked_analysis = replace(
                analysis,
                facts=tuple(
                    replace(fact, evidence=MASKED_VALUE, details={})
                    if fact.sensitive else fact
                    for fact in analysis.facts
                ),
                concepts=tuple(
                    replace(
                        concept,
                        evidence=tuple(
                            item.masked(MASKED_VALUE)
                            for item in concept.evidence
                        ),
                    )
                    for concept in analysis.concepts
                ),
                providers=tuple(
                    replace(
                        provider,
                        evidence=tuple(
                            item.masked(MASKED_VALUE)
                            for item in provider.evidence
                        ),
                    )
                    for provider in analysis.providers
                ),
            )
            view = replace(view, semantic_analysis=masked_analysis)
        finding_views.append(view)

    return finding_views
