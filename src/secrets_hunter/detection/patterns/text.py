import re


ACRONYM_BOUNDARY_RE = re.compile(r"([A-Z]+)([A-Z][a-z])")
LOWER_OR_DIGIT_TO_UPPER_BOUNDARY_RE = re.compile(r"([a-z\d])([A-Z])")
NON_ALPHANUMERIC_RE = re.compile(r"[^A-Za-z0-9]+")
NON_LOWERCASE_ASCII_RE = re.compile(r"[^a-z]")
TEXT_TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,63}")
