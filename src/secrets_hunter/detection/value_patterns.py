import re


VALUE_BOUNDARY_CHARS = '.,;:()[]{}<>"\'`'

JWT_TOKEN_BODY_PATTERN = (
    r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*"
)
JWT_TOKEN_PATTERN = rf"\b{JWT_TOKEN_BODY_PATTERN}\b"
JWT_TOKEN_RE = re.compile(JWT_TOKEN_PATTERN)
JWT_TOKEN_VALUE_RE = re.compile(rf"^{JWT_TOKEN_BODY_PATTERN}$")

UUID_VALUE_RE = re.compile(
    r"^[0-9a-fA-F]{8}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{12}$"
)

CREDENTIAL_URI_RE = re.compile(
    r"(?:postgresql|postgres|mysql|mongodb(?:\+srv)?|redis|rediss|amqp|amqps|jdbc:[a-z]+)"
    r"://[^:/@]+:[^@/\s]+@[^\s'\"`]+"
)
DB_PASSWORD_IN_URI_RE = re.compile(r"://[^:/@]+:([^@/\s]+)@")
DB_PLACEHOLDER_RE = re.compile(
    r"%[A-Za-z]|\$\{[^}]+}|\{[^}]+}|<[^<>]+>"
)
HEX_VALUE_RE = re.compile(r"^[0-9A-Fa-f]+$")
BASE64_STANDARD_VALUE_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
BASE64URL_VALUE_RE = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")
