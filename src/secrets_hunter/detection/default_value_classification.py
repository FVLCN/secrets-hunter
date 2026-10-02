from secrets_hunter.detection.value_classification import (
    EntropyFamily,
    ValueClassificationPlan,
    ValueKindSpec
)
from secrets_hunter.detection.value_patterns import (
    BASE64_STANDARD_VALUE_RE,
    BASE64URL_VALUE_RE,
    CREDENTIAL_URI_RE,
    HEX_VALUE_RE,
    JWT_TOKEN_VALUE_RE,
    UUID_VALUE_RE
)
from secrets_hunter.models import ValueKind


DEFAULT_VALUE_KIND_SPECS = (
    ValueKindSpec(ValueKind.JWT, (JWT_TOKEN_VALUE_RE,)),
    ValueKindSpec(ValueKind.UUID, (UUID_VALUE_RE,)),
    ValueKindSpec(ValueKind.CREDENTIAL_URI, (CREDENTIAL_URI_RE,)),
    ValueKindSpec(
        ValueKind.HEX,
        (HEX_VALUE_RE,),
        EntropyFamily.HEX
    ),
    ValueKindSpec(
        ValueKind.BASE64_LIKE,
        (BASE64_STANDARD_VALUE_RE, BASE64URL_VALUE_RE),
        EntropyFamily.BASE64
    ),
    ValueKindSpec(
        ValueKind.BASE64,
        (BASE64_STANDARD_VALUE_RE,),
        EntropyFamily.BASE64
    ),
    ValueKindSpec(
        ValueKind.BASE64URL,
        (BASE64URL_VALUE_RE,),
        EntropyFamily.BASE64
    )
)


def build_default_value_classifier() -> ValueClassificationPlan:
    return ValueClassificationPlan(DEFAULT_VALUE_KIND_SPECS)
