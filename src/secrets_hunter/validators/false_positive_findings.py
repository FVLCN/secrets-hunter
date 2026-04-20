import base64
import re

from binascii import Error as BinasciiError

from secrets_hunter.models import Finding, DBConnectionFragment, PEMKeyFragment
from secrets_hunter.models.config import ExcludePattern

# Special patterns
PUBLIC_PEM = ExcludePattern(name="Public", category="Key", pattern=re.compile("PUBLIC"))
CERT = ExcludePattern(name="Public", category="Certificate", pattern=re.compile("CERTIFICATE"))
SEMANTICS = ExcludePattern(name="Semantics -", category="string with English-like words", pattern=re.compile(''))
MISSING_PEM_BODY = ExcludePattern(name="Missing", category="PEM body", pattern=re.compile(''))
MISSING_PEM_FOOTER = ExcludePattern(name="Missing", category="PEM footer", pattern=re.compile(''))
INVALID_PEM_BODY = ExcludePattern(name="Invalid", category="PEM base64 body", pattern=re.compile(''))
DB_CONN_PLACEHOLDER = ExcludePattern(
    name="db connection", category="placeholder", pattern=re.compile(r'%[a-zA-Z]|\{.*?}|\$\{.*?}')
)


class FalsePositiveFindingsValidator:
    def __init__(self, exclude_patterns, exclude_keywords, string_semantics_classifier):
        self.exclude_patterns = exclude_patterns
        self.exclude_keywords = exclude_keywords
        self.string_classifier = string_semantics_classifier

    @staticmethod
    def check_rejection_for_pem_header(pem_header: str) -> tuple[bool, ExcludePattern | None]:
        if re.search(PUBLIC_PEM.pattern, pem_header):
            return True, PUBLIC_PEM

        if re.search(CERT.pattern, pem_header):
            return True, CERT

        return False, None

    def check_rejection_for_pem_key(self, pem_key: PEMKeyFragment) -> tuple[bool, ExcludePattern | None]:
        pem_header = pem_key.header or ""
        rejected, reason = self.check_rejection_for_pem_header(pem_header)

        if rejected:
            return True, reason

        if not pem_key.body:
            return True, MISSING_PEM_BODY

        if not pem_key.footer:
            return True, MISSING_PEM_FOOTER

        normalized_body = "".join(pem_key.body.split())

        if not self.is_valid_base64_body(normalized_body):
            return True, INVALID_PEM_BODY

        return False, None

    @staticmethod
    def is_valid_base64_body(body: str) -> bool:
        if not body:
            return False

        try:
            base64.b64decode(body, validate=True)
            return True
        except (ValueError, BinasciiError):
            return False

    def check_rejection_for_db_conn_string(self, db_conn_string: str) -> tuple[bool, ExcludePattern | None]:
        password_match = re.search(r'://[^:/@]+:([^@/\s]+)@', db_conn_string)

        if not password_match:
            return False, None

        password = password_match.group(1)

        if re.search(DB_CONN_PLACEHOLDER.pattern, password):
            return True, DB_CONN_PLACEHOLDER

        for ep in self.exclude_patterns:
            if ep.category == "placeholder" and re.search(ep.pattern, password):
                return True, ep

        classification = self.string_classifier.classify(password)

        if classification.structured:
            return True, SEMANTICS

        return False, None

    def check_rejection_for_generic_string(self, finding: Finding) -> tuple[bool, ExcludePattern | None]:
        string = finding.match
        string_lower = string.lower()

        for exclude_pattern in self.exclude_patterns:
            pattern = exclude_pattern.pattern

            if re.search(pattern, string_lower):
                if pattern.pattern == "test" and "sk_test" in string_lower:
                    continue

                return True, exclude_pattern

        string_semantics_classification = self.string_classifier.classify(string)

        if string_semantics_classification.structured:
            return True, SEMANTICS

        return False, None

    def check_rejection_for_finding_value(self, finding: Finding) -> tuple[bool, ExcludePattern | None]:
        match = finding.match
        fragment = finding.fragment

        if isinstance(fragment, PEMKeyFragment):
            return self.check_rejection_for_pem_key(fragment)
        elif isinstance(fragment, DBConnectionFragment):
            return self.check_rejection_for_db_conn_string(match)

        return self.check_rejection_for_generic_string(finding)

    def check_rejection_for_keywords(self, kws: list[str]) -> tuple[bool, str]:
        exclude = [k.lower() for k in self.exclude_keywords if k]

        for kw in kws:
            kw_lower = (kw or "").lower()

            for ex in exclude:
                if ex in kw_lower:
                    return True, ex

        return False, ""
