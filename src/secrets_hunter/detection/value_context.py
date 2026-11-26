import ast
import base64
import re
import textwrap
import xml.etree.ElementTree as ET
import zlib

from functools import lru_cache

from secrets_hunter.detection.fragmenter.models import SourceContext
from secrets_hunter.detection.patterns.git_references import (
    ACTION_COMMIT_SHA_RE,
    ACTION_REFERENCE_RE,
    COMMENT_VALUE_REFERENCE_PATTERN,
)
from secrets_hunter.detection.patterns.javascript import (
    JS_CREATE_HASH_UPDATE_RE,
    JS_TOKEN_RE,
)
from secrets_hunter.detection.patterns.values import (
    BASE64_WITH_WHITESPACE_BYTES_RE,
    WHITESPACE_BYTES_RE,
)
from secrets_hunter.detection.semantics.observation.facts import FactId, make_fact
from secrets_hunter.detection.source_languages import is_js_ts_source
from secrets_hunter.models.fact import Fact


MAX_CONTEXT_LINES = 32
MAX_CONTEXT_BYTES = 4096
MAX_DECODED_BYTES = 16384
_MAX_CACHED_JS_LINE_CHARS = 1024
_HASH_NAMES = frozenset({
    "hash", "md5", "sha1", "sha224", "sha256", "sha384", "sha512",
    "sha256Hash", "hashSecretKey", "hashAPIKey"
})
_SAML_AUTHN_REQUEST_FACT = make_fact(
    FactId.SAML_AUTHN_REQUEST_VALUE,
    "AuthnRequest element in namespace urn:oasis:names:tc:SAML:2.0:protocol",
)


def _is_authn_request(value: str) -> bool:
    raw = value.encode("utf-8")
    if len(raw) > MAX_CONTEXT_BYTES:
        return False

    candidates = [raw]
    if BASE64_WITH_WHITESPACE_BYTES_RE.fullmatch(raw):
        try:
            decoded = base64.b64decode(WHITESPACE_BYTES_RE.sub(b"", raw), validate=True)
            candidates.append(decoded)
            decoder = zlib.decompressobj(-15)
            inflated = decoder.decompress(decoded, MAX_DECODED_BYTES + 1)
            if (
                decoder.eof
                and not decoder.unconsumed_tail
                and not decoder.unused_data
                and len(inflated) <= MAX_DECODED_BYTES
            ):
                candidates.append(inflated)
        except (ValueError, zlib.error):
            pass

    for candidate in candidates:
        if len(candidate) > MAX_DECODED_BYTES:
            continue
        try:
            xml = candidate.decode("utf-8")
            if "\x00" in xml or "<!DOCTYPE" in xml or "<!ENTITY" in xml:
                continue
            root = ET.fromstring(xml)
            if root.tag == "{urn:oasis:names:tc:SAML:2.0:protocol}AuthnRequest":
                return True
        except (ET.ParseError, ValueError):
            pass

    return False


def _name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _hash_call(node: ast.AST) -> bool:
    if not isinstance(node, ast.Call):
        return False
    if _name(node.func) in _HASH_NAMES:
        return True
    return (
        isinstance(node.func, ast.Attribute)
        and node.func.attr in ("hexdigest", "digest")
        and _hash_call(node.func.value)
    )


def _hash_operand(node: ast.AST) -> bool:
    return _hash_call(node) or (
        isinstance(node, ast.Subscript)
        and isinstance(node.slice, ast.Constant)
        and str(node.slice.value).lower() in ("hash", "digest", "checksum")
    )


def _hash_call_label(node: ast.Call) -> str:
    if (
        isinstance(node.func, ast.Attribute)
        and node.func.attr in ("hexdigest", "digest")
        and isinstance(node.func.value, ast.Call)
    ):
        return f"{_hash_call_label(node.func.value)}.{node.func.attr}()"
    return f"{_name(node.func)}()"


@lru_cache(maxsize=256)
def _python_statement(text: str) -> ast.Module | None:
    try:
        tree = ast.parse(textwrap.dedent(text))
        return tree if len(tree.body) == 1 else None
    except (SyntaxError, ValueError, RecursionError):
        return None


def _python_facts(
    lines: list[str],
    line: int,
    value: str
) -> dict[FactId, Fact]:
    facts: dict[FactId, Fact] = {}
    index = line - 1
    for start in range(index, -1, -1):
        for end in range(index + 1, len(lines) + 1):
            tree = _python_statement("".join(lines[start:end]))
            if tree is None:
                continue
            literals = [
                node for node in ast.walk(tree)
                if isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and node.lineno <= line - start <= node.end_lineno
                and value in node.value
            ]
            for literal in literals:
                if _is_authn_request(literal.value):
                    facts[FactId.SAML_AUTHN_REQUEST_VALUE] = _SAML_AUTHN_REQUEST_FACT
                for node in ast.walk(tree):
                    if not isinstance(node, ast.Call):
                        continue
                    if _hash_call(node) and any(arg is literal for arg in node.args):
                        facts[FactId.HASH_CALL_ARGUMENT] = make_fact(
                            FactId.HASH_CALL_ARGUMENT,
                            _hash_call_label(node),
                        )
                    if _name(node.func) in ("assertEqual", "assertEquals") and len(node.args) == 2:
                        left, right = node.args
                        for expected, other in ((left, right), (right, left)):
                            if expected is literal and _hash_operand(other):
                                operand = (
                                    _hash_call_label(other)
                                    if isinstance(other, ast.Call)
                                    else f'lookup key "{other.slice.value}"'
                                )
                                facts[FactId.ASSERTED_HASH_VALUE] = make_fact(
                                    FactId.ASSERTED_HASH_VALUE,
                                    f"{_name(node.func)}() compares the value with {operand}",
                                )

    return facts


def _tokenize_js(current: str) -> tuple[tuple[str | None, str, int], ...]:
    return tuple(
        (match.lastgroup, match.group(), match.start())
        for match in JS_TOKEN_RE.finditer(current)
        if match.lastgroup not in ("space", "comment")
    )


_cached_js_tokens = lru_cache(maxsize=256)(_tokenize_js)


def _js_facts(current: str, value: str) -> dict[FactId, Fact]:
    tokens = (
        _cached_js_tokens(current)
        if len(current) <= _MAX_CACHED_JS_LINE_CHARS
        else _tokenize_js(current)
    )
    hits = [
        index for index, (kind, text, _) in enumerate(tokens)
        if kind == "string" and value in text[1:-1] and "${" not in text
    ]
    if len(hits) != 1:
        return {}

    hit = hits[0]
    stack: list[int] = []
    pairs: dict[int, int] = {}
    for index, (_, text, _) in enumerate(tokens):
        if text in ("(", "[", "{"):
            stack.append(index)
        elif text in (")", "]", "}") and stack:
            opening = stack[-1]
            if (tokens[opening][1], text) in (("(", ")"), ("[", "]"), ("{", "}")):
                pairs[opening] = index
                stack.pop()
            else:
                return {}

    calls: list[tuple[int, int, str, list[tuple[int, int]], bool]] = []
    for opening, closing in pairs.items():
        if tokens[opening][1] != "(" or opening == 0 or tokens[opening - 1][0] != "name":
            continue
        name = tokens[opening - 1][1]
        args: list[tuple[int, int]] = []
        cursor = opening + 1
        arg_start = cursor
        while cursor < closing:
            if cursor in pairs:
                cursor = pairs[cursor] + 1
                continue
            if tokens[cursor][1] == ",":
                args.append((arg_start, cursor))
                arg_start = cursor + 1
            cursor += 1
        if arg_start < closing:
            args.append((arg_start, closing))
        is_hash = name in _HASH_NAMES or (
            name == "update" and bool(JS_CREATE_HASH_UPDATE_RE.search(
                current[:tokens[opening][2]]
            ))
        )
        calls.append((opening, closing, name, args, is_hash))

    facts: dict[FactId, Fact] = {}
    for _, _, name, args, is_hash in calls:
        if is_hash and args and args[0] == (hit, hit + 1):
            label = "createHash(...).update()" if name == "update" else f"{name}()"
            facts[FactId.HASH_CALL_ARGUMENT] = make_fact(
                FactId.HASH_CALL_ARGUMENT,
                label,
            )
        if name in ("equal", "strictEqual", "deepEqual") and len(args) == 2:
            left, right = args
            for expected, other in ((left, right), (right, left)):
                if expected == (hit, hit + 1):
                    for opening, closing, hash_name, _, hashed in calls:
                        if hashed and other[0] <= opening - 1 and closing < other[1]:
                            label = (
                                "createHash(...).update()"
                                if hash_name == "update"
                                else f"{hash_name}()"
                            )
                            facts[FactId.ASSERTED_HASH_VALUE] = make_fact(
                                FactId.ASSERTED_HASH_VALUE,
                                f"{name}() compares the value with {label}",
                            )
                            break
    if _is_authn_request(value):
        facts[FactId.SAML_AUTHN_REQUEST_VALUE] = _SAML_AUTHN_REQUEST_FACT

    return facts


def value_context_facts(
    context: SourceContext | None,
    *,
    candidate_line: int,
    candidate_value: str,
    file_path: str
) -> frozenset[FactId]:
    return frozenset(value_context_fact_records(
        context,
        candidate_line=candidate_line,
        candidate_value=candidate_value,
        file_path=file_path,
    ))


def value_context_fact_records(
    context: SourceContext | None,
    *,
    candidate_line: int,
    candidate_value: str,
    file_path: str
) -> dict[FactId, Fact]:
    if context is None or not candidate_value:
        return {}

    text = context.content
    if len(text.encode("utf-8")) > MAX_CONTEXT_BYTES:
        return {}
    lines = text.splitlines(keepends=True)
    line = candidate_line - context.start_line + 1
    if len(lines) > MAX_CONTEXT_LINES or not 1 <= line <= len(lines):
        return {}
    current = lines[line - 1]
    if current.count(candidate_value) != 1:
        return {}

    if candidate_value == text.strip() and _is_authn_request(candidate_value):
        return {FactId.SAML_AUTHN_REQUEST_VALUE: _SAML_AUTHN_REQUEST_FACT}
    if file_path.endswith((".yml", ".yaml")):
        match = ACTION_REFERENCE_RE.fullmatch(current)
        if match and (
            candidate_value == match["pin"]
            or match["comment"] and ACTION_COMMIT_SHA_RE.fullmatch(candidate_value)
            and re.search(
                COMMENT_VALUE_REFERENCE_PATTERN.format(value=re.escape(candidate_value)),
                match["comment"],
            )
        ):
            role = "commit pin" if candidate_value == match["pin"] else "comment hash"
            return {FactId.ACTION_REFERENCE_LITERAL: make_fact(
                FactId.ACTION_REFERENCE_LITERAL,
                f"{role} in uses: {match['action']}@…",
            )}
    if file_path.endswith(".py"):
        return _python_facts(lines, line, candidate_value)
    if is_js_ts_source(file_path):
        return _js_facts(current, candidate_value)
    if _is_authn_request(candidate_value):
        return {FactId.SAML_AUTHN_REQUEST_VALUE: _SAML_AUTHN_REQUEST_FACT}

    return {}
