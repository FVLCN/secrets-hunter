from secrets_hunter.models import Finding
from secrets_hunter.config.settings import CLIArgs, PEM_BEGIN_RE, PEM_END_RE

PEM_HEAD_LINES = 4
PEM_TAIL_LINES = 4
GENERIC_HEAD_CHARS = 80
GENERIC_TAIL_CHARS = 80


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
        lines[-1],
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


class FindingsProcessor:
    @staticmethod
    def process(findings: list[Finding], config: CLIArgs) -> list[Finding]:
        """Filter, mask, and sort findings."""
        output_findings: list[Finding] = []

        for finding in findings:
            if finding.confidence < config.min_confidence:
                continue

            if config.truncate_long_matches:
                finding = finding.with_match(truncate_match(finding.match))

            if not config.reveal_findings:
                finding = finding.mask()

            output_findings.append(finding)

        output_findings.sort(key=lambda f: f.confidence, reverse=True)
        return output_findings
