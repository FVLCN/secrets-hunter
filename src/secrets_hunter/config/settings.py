import re

from dataclasses import dataclass


HEX_ENTROPY_MAX = 4.5
B64_ENTROPY_MAX = 6.0
MAX_WORKERS_MULTIPLIER = 2
MIN_PEM_BODY_BYTES = 16
STRIP = '.,;:()[]{}<>"\'`'

PEM_TYPES = [
    "PRIVATE KEY",
    "PUBLIC KEY",
    "CERTIFICATE",
    "RSA PRIVATE KEY",
    "RSA PUBLIC KEY",
    "EC PRIVATE KEY",
    "DSA PRIVATE KEY",
    "OPENSSH PRIVATE KEY",
    "ENCRYPTED PRIVATE KEY",
    "CERTIFICATE REQUEST",
    "CRL",
    "PGP PUBLIC KEY BLOCK",
    "PGP PRIVATE KEY BLOCK"
]

pem_group = "|".join(PEM_TYPES)

PEM_BEGIN_RE = re.compile(rf'-----BEGIN ({pem_group})-----')
PEM_END_RE   = re.compile(rf'-----END ({pem_group})-----')
DB_URI_RE = re.compile(
    r'(?:postgresql|postgres|mysql|mongodb(?:\+srv)?|redis|rediss|amqp|amqps|jdbc:[a-z]+)'
    r'://[^:/@]+:[^@/\s]+@[^\s\'"`]+'
)

class FileSettings:
    MAX_LINE_LENGTH = 50000
    MAX_REPEAT_RUN = 1000
    BINARY_DETECTION_CHUNK_SIZE = 2048
    CONTROL_CHARS_RATIO_THRESHOLD = 0.05


class CLIDefaults:
    HEX_ENTROPY_THRESHOLD = 3.0
    B64_ENTROPY_THRESHOLD = 4.25
    MIN_STRING_LENGTH = 10
    MIN_CONFIDENCE = 0
    MAX_WORKERS = 4
    FAIL_ON_FINDINGS = False
    REVEAL_FINDINGS = False
    TRUNCATE_LONG_MATCHES = False
    LOG_LEVEL = "INFO"


@dataclass
class CLIArgs:
    hex_entropy_threshold: float = CLIDefaults.HEX_ENTROPY_THRESHOLD
    b64_entropy_threshold: float = CLIDefaults.B64_ENTROPY_THRESHOLD
    min_string_length: int = CLIDefaults.MIN_STRING_LENGTH
    min_confidence: int = CLIDefaults.MIN_CONFIDENCE
    max_workers: int = CLIDefaults.MAX_WORKERS
    fail_on_findings: bool = CLIDefaults.FAIL_ON_FINDINGS
    reveal_findings: bool = CLIDefaults.REVEAL_FINDINGS
    truncate_long_matches: bool = CLIDefaults.TRUNCATE_LONG_MATCHES
    log_level: str = CLIDefaults.LOG_LEVEL

    @classmethod
    def from_argparse(cls, args):
        return cls(
            hex_entropy_threshold=args.hex_entropy,
            b64_entropy_threshold=args.b64_entropy,
            min_string_length=args.min_length,
            min_confidence=args.min_confidence,
            max_workers=args.workers,
            fail_on_findings=args.fail_on_findings,
            reveal_findings=args.reveal_findings,
            truncate_long_matches=args.truncate_long_matches,
            log_level=args.log_level
        )
