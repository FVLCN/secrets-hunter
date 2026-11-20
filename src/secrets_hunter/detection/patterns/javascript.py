import re


JS_IDENTIFIER_RE = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*\Z")
JS_STRING_PATTERN = (
    r'''"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`'''
)
JS_COMMENT_PATTERN = r"//[^\n]*|/\*[\s\S]*?\*/"
JS_NON_CODE_RE = re.compile(f"{JS_STRING_PATTERN}|{JS_COMMENT_PATTERN}")
JS_IMPORT_CONTEXT_RE = re.compile(r"\bimport\b[^;]*$")
JS_DECLARATION_CONTEXT_RE = re.compile(
    r"\b(?:typeof|const|let|var|function|class|interface|type)\s*$"
)
JS_TYPE_PREDICATE_CONTEXT_RE = re.compile(r":\s*[A-Za-z_$][\w$]*\s+is\s*$")
JS_AS_CONTEXT_RE = re.compile(r"\bas\s*$")
JS_TYPE_UNION_CONTEXT_RE = re.compile(
    r"\btype\s+[A-Za-z_$][\w$]*\s*=[^;]*\|\s*$"
)
JS_REFERENCE_ARRAY_CONTEXT_RE = re.compile(
    r"\b(?:exports|providers|type)\s*:\s*\[\s*"
    r"(?:[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*\s*,\s*)*$"
)
JS_IDENTIFIER_OCCURRENCE_PATTERN = r"(?<![\w$]){value}(?![\w$])"
JS_TOKEN_RE = re.compile(
    rf"(?P<space>\s+)|(?P<comment>{JS_COMMENT_PATTERN})"
    rf"|(?P<string>{JS_STRING_PATTERN})"
    r"|(?P<name>[A-Za-z_$][\w$]*)|(?P<symbol>.)"
)
JS_CREATE_HASH_UPDATE_RE = re.compile(
    r"\bcreateHash\s*\([^)]*\)\s*\.\s*update\s*$"
)
