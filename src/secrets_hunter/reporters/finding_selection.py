from collections.abc import Iterable

from secrets_hunter.config import FindingSelectionOptions
from secrets_hunter.config.validation import FindingSelectionOptionsValidator
from secrets_hunter.models import Finding


def select_for_reporting(
    findings: Iterable[Finding],
    options: FindingSelectionOptions
) -> list[Finding]:
    """Select and order findings according to the reporting threshold."""
    FindingSelectionOptionsValidator.validate(options)
    selected = (
        finding
        for finding in findings
        if finding.confidence >= options.min_confidence
    )
    return sorted(
        selected,
        key=lambda finding: finding.confidence,
        reverse=True
    )
