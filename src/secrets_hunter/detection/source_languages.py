from pathlib import PurePath


JS_TS_EXTENSIONS = frozenset({
    ".js", ".jsx", ".mjs", ".cjs",
    ".ts", ".tsx", ".mts", ".cts",
})


def is_js_ts_source(path: str | PurePath) -> bool:
    return PurePath(path).suffix.lower() in JS_TS_EXTENSIONS
