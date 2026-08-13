from __future__ import annotations

import re

_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|secret|token|api[_-]?key|authorization)\s*[:=]\s*([^\s,;]+)"
)


def redact_text(value: str) -> str:
    """Redact common inline secret assignments without altering ordinary analyst prose."""
    return _SECRET_ASSIGNMENT.sub(lambda match: f"{match.group(1)}=[REDACTED]", value)


def redact_metadata(value: object) -> object:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {str(key): redact_metadata(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_metadata(item) for item in value]
    return value
