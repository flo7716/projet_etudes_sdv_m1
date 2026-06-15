# app/modules/report/utils.py
import re
from typing import Any

_UNICODE_REPLACEMENTS = {
    "\u2192": "->", "\u2190": "<-", "\u2013": "-", "\u2014": "--",
    "\u2018": "'", "\u2019": "'", "\u201c": '"', "\u201d": '"',
    "\u00bf": "", "\u00ab": '"', "\u00bb": '"',
}

def _escape_latex(text: str) -> str:
    replacements = {
        "\\": "\\textbackslash{}", "%": "\\%", "$": "\\$", "#": "\\#",
        "&": "\\&", "_": "\\_", "{": "\\{", "}": "\\}",
        "~": "\\textasciitilde{}", "^": "\\textasciicircum{}",
    }
    for k, v in replacements.items():
        text = text.replace(k, v)
    return text

def _clean_text(text: str) -> str:
    ansi_escape = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
    text = ansi_escape.sub("", text)
    for src, dst in _UNICODE_REPLACEMENTS.items():
        text = text.replace(src, dst)
    return "".join(ch for ch in text if (32 <= ord(ch) < 127) or ch in "\n\r\t")

def _sanitize_data(data: Any) -> Any:
    if isinstance(data, str):
        return _clean_text(data)
    if isinstance(data, dict):
        return {k: _sanitize_data(v) for k, v in data.items()}
    if isinstance(data, list):
        return [_sanitize_data(v) for v in data]
    return data

def _extract_text(value: Any) -> str:
    if isinstance(value, str):
        return _clean_text(value)
    if isinstance(value, dict):
        return ", ".join(f"{k}={_extract_text(v)}" for k, v in value.items())
    if isinstance(value, list):
        return " | ".join(_extract_text(item) for item in value if _extract_text(item))
    return str(value)

def _truncate_text(text: str, length: int = 85) -> str:
    cleaned = _clean_text(text).strip()
    return cleaned if len(cleaned) <= length else cleaned[:length - 3] + "..."