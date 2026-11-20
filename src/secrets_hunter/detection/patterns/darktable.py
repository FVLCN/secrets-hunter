import re


DARKTABLE_PARAMETER_RE = re.compile(
    r'''(?<![\w:.-])darktable:(?:blendop_params|params)\s*=\s*(["'])([^"'<>]*)\1'''
)
DARKTABLE_HEX_VALUE_RE = re.compile(r"(?:[0-9a-fA-F]{2})+")
DARKTABLE_COMPRESSED_VALUE_RE = re.compile(
    r"gz(?:0[1-9]|[1-9][0-9])[A-Za-z0-9+/]+={0,2}"
)
