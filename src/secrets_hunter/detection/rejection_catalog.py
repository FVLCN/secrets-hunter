from dataclasses import dataclass

from secrets_hunter.models import (
    RejectionEvidence,
    RejectionEvidenceId,
    RejectionEvidenceKind,
    RejectionId,
    RejectionKind,
    RejectionReason,
)


@dataclass(frozen=True)
class EvidencePresentation:
    kind: RejectionEvidenceKind
    fixed_match: str | None = None


@dataclass(frozen=True)
class RejectionPresentation:
    label: str
    name: str
    category: str


REJECTION_PRESENTATIONS = {
    RejectionId.GIT_SIGNING_KEY_REFERENCE: RejectionPresentation(
        "Git signing key reference", "Git signing key", "key reference"
    ),
    RejectionId.DARKTABLE_PARAMETER: RejectionPresentation(
        "Darktable image-processing parameter",
        "Darktable",
        "image-processing parameters",
    ),
    RejectionId.CODE_IDENTIFIER_REFERENCE: RejectionPresentation(
        "Code identifier reference", "Code", "identifier reference"
    ),
    RejectionId.GIT_COMMIT_REFERENCE: RejectionPresentation(
        "Git commit reference", "Git commit", "reference"
    ),
    RejectionId.PUBLIC_SSH_KEY: RejectionPresentation(
        "Public SSH key", "Public", "SSH key"
    ),
    RejectionId.PUBLIC_PAYMENT_ADDRESS: RejectionPresentation(
        "Public payment address", "Public", "payment address"
    ),
    RejectionId.ABBREVIATED_JWT_EXAMPLE: RejectionPresentation(
        "Abbreviated JWT example", "Abbreviated", "JWT example"
    ),
}


EVIDENCE_PRESENTATIONS = {
    RejectionEvidenceId.GIT_CONFIG_PATH: EvidencePresentation(
        RejectionEvidenceKind.PATH,
    ),
    RejectionEvidenceId.GPG_KEY_ID_FORMAT: EvidencePresentation(
        RejectionEvidenceKind.VALUE_SHAPE,
        "GPG key ID format",
    ),
    RejectionEvidenceId.DARKTABLE_FILE_EXTENSION: EvidencePresentation(
        RejectionEvidenceKind.PATH,
    ),
    RejectionEvidenceId.DARKTABLE_PARAMETER_NAME: EvidencePresentation(
        RejectionEvidenceKind.SOURCE_CONTEXT,
    ),
    RejectionEvidenceId.DARKTABLE_HEX_PARAMETER: EvidencePresentation(
        RejectionEvidenceKind.VALUE_SHAPE,
        "Darktable hex parameter",
    ),
    RejectionEvidenceId.DARKTABLE_COMPRESSED_PARAMETER: EvidencePresentation(
        RejectionEvidenceKind.VALUE_SHAPE,
        "compressed Darktable parameter",
    ),
    RejectionEvidenceId.CODE_FILE_EXTENSION: EvidencePresentation(
        RejectionEvidenceKind.PATH,
    ),
    RejectionEvidenceId.JS_TS_IDENTIFIER_USE: EvidencePresentation(
        RejectionEvidenceKind.SOURCE_CONTEXT,
        "JavaScript/TypeScript identifier use",
    ),
    RejectionEvidenceId.GIT_COMMIT_URL_CONTEXT: EvidencePresentation(
        RejectionEvidenceKind.SOURCE_CONTEXT,
        "commit URL reference",
    ),
    RejectionEvidenceId.ACTION_COMMIT_PIN_CONTEXT: EvidencePresentation(
        RejectionEvidenceKind.SOURCE_CONTEXT,
        "pinned action commit reference",
    ),
    RejectionEvidenceId.ACTION_COMMIT_COMMENT_CONTEXT: EvidencePresentation(
        RejectionEvidenceKind.SOURCE_CONTEXT,
        "action comment commit reference",
    ),
    RejectionEvidenceId.SSH_PUBLIC_KEY_FORMAT: EvidencePresentation(
        RejectionEvidenceKind.VALUE_SHAPE,
        "SSH public key format",
    ),
    RejectionEvidenceId.BASE58CHECK_PAYMENT_ADDRESS: EvidencePresentation(
        RejectionEvidenceKind.VALUE_SHAPE,
        "Base58Check public payment address",
    ),
    RejectionEvidenceId.ABBREVIATED_JWT_CONTEXT: EvidencePresentation(
        RejectionEvidenceKind.SOURCE_CONTEXT,
        "abbreviated JWT example",
    ),
}

EVIDENCE_TEMPLATES = {
    RejectionEvidenceKind.PATH: 'Path contains "{evidence}"',
    RejectionEvidenceKind.SOURCE_CONTEXT: 'Source matches "{evidence}"',
    RejectionEvidenceKind.VALUE_SHAPE: 'Value matches "{evidence}"',
}


def rejection_label(reason: RejectionReason) -> str | None:
    if reason.reason_id is None:
        return None
    return REJECTION_PRESENTATIONS[reason.reason_id].label


def make_rejection_reason(
    reason_id: RejectionId,
    kind: RejectionKind,
    *,
    evidence: tuple[RejectionEvidence, ...] = (),
    detail: str | None = None,
) -> RejectionReason:
    presentation = REJECTION_PRESENTATIONS[reason_id]
    return RejectionReason(
        kind=kind,
        name=presentation.name,
        category=presentation.category,
        detail=detail,
        reason_id=reason_id,
        evidence=evidence,
    )


def present_rejection_evidence(
    evidence: RejectionEvidence,
) -> tuple[RejectionEvidenceKind, str, str, RejectionEvidenceId]:
    presentation = EVIDENCE_PRESENTATIONS[evidence.id]
    match = (
        evidence.match
        if evidence.match is not None
        else presentation.fixed_match
    )
    if match is None:
        raise ValueError(f"Rejection evidence {evidence.id!r} has no match")

    return (
        presentation.kind,
        match,
        EVIDENCE_TEMPLATES[presentation.kind],
        evidence.id,
    )
