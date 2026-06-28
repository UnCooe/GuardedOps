from __future__ import annotations

import re

SECRET_KEY_RE = re.compile(r"(secret|token|password|passwd|api[_-]?key|credential|authorization|cookie)", re.I)
AUTHORIZATION_RE = re.compile(r"(?i)(authorization\s*:\s*)([^\r\n]+)")
SENSITIVE_OUTPUT_RE = re.compile(
    r"(?i)(authorization|cookie|token|secret|password|passwd|api[_-]?key)(\s*[:=]\s*)([^\r\n\s]+)"
)


def key_is_secret(key_path: str) -> bool:
    return bool(SECRET_KEY_RE.search(key_path))


def redact_text(text: str) -> str:
    text = AUTHORIZATION_RE.sub(r"\1<redacted>", text)
    return SENSITIVE_OUTPUT_RE.sub(r"\1\2<redacted>", text)


def redact_value(key_path: str, value: object) -> object:
    if key_is_secret(key_path):
        return "<redacted>"
    return value
