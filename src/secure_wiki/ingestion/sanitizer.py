"""Sanitizing pass for the ingestion layer (Spec 4.1).

Detects and flags common injection obfuscation vectors BEFORE source text
reaches a model. Flagged content is NOT silently discarded but logged
(forensically relevant, Spec 4.1).

Status: PARTIALLY IMPLEMENTED. Detection patterns are functional; integration
with structured logging and pipeline hookup are TODO.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field


# Invisible / dangerous Unicode codepoints (zero-width, bidi-override).
_INVISIBLE_CODEPOINTS = {
    "\u200b", "\u200c", "\u200d", "\ufeff",  # zero-width space/joiner/BOM
    "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",  # bidi overrides
    "\u2066", "\u2067", "\u2068", "\u2069",  # isolates
}

# Heuristic instruction patterns (Spec 4.1). Intentionally broad; false positives
# are flagged, not removed — the decision is made by a later stage.
_INSTRUCTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.I),
    re.compile(r"disregard\s+(the\s+)?above", re.I),
    re.compile(r"\bsystem\s*:", re.I),
    re.compile(r"you\s+are\s+now\b", re.I),
    re.compile(r"du\s+bist\s+(jetzt|ab\s+jetzt)\b", re.I),
    re.compile(r"ab\s+jetzt\s+(ignoriere|vertraue)", re.I),
    re.compile(r"new\s+(instructions|rules)\s*:", re.I),
]

# Versteckte-Payload-Marker.
_HTML_COMMENT = re.compile(r"<!--.*?-->", re.S)
_HIDDEN_STYLE = re.compile(r"(display\s*:\s*none|color\s*:\s*#?fff)", re.I)
_LONG_B64 = re.compile(r"\b[A-Za-z0-9+/]{120,}={0,2}\b")


@dataclass
class SanitizeReport:
    """Result of a sanitizing pass."""
    cleaned_text: str
    flags: list[str] = field(default_factory=list)

    @property
    def is_suspicious(self) -> bool:
        return bool(self.flags)


def sanitize(text: str) -> SanitizeReport:
    """Normalize text and flag obfuscation vectors (Spec 4.1).

    Returns the cleaned text plus a list of flags. Removes invisible characters
    but keeps visually suspicious patterns intact and only flags them — the
    source remains readable for later processing stages.
    """
    flags: list[str] = []

    # 1) Remove and flag invisible codepoints.
    found_invisible = {c for c in text if c in _INVISIBLE_CODEPOINTS}
    if found_invisible:
        flags.append(f"invisible_chars:{len(found_invisible)}")
    cleaned = "".join(c for c in text if c not in _INVISIBLE_CODEPOINTS)

    # 2) Flag other control characters (except whitespace).
    if any(unicodedata.category(c) == "Cc" and c not in "\t\n\r" for c in cleaned):
        flags.append("control_chars")

    # 3) Versteckte Payloads.
    if _HTML_COMMENT.search(cleaned):
        flags.append("html_comment")
    if _HIDDEN_STYLE.search(cleaned):
        flags.append("hidden_style")
    if _LONG_B64.search(cleaned):
        flags.append("long_base64_block")

    # 4) Instruktionsmuster.
    for pat in _INSTRUCTION_PATTERNS:
        if pat.search(cleaned):
            flags.append(f"instruction_pattern:{pat.pattern[:30]}")

    return SanitizeReport(cleaned_text=cleaned, flags=flags)


# TODO:
#   - Wire flags into a structured audit log (Spec 4.1, "logged").
#   - Define threshold policy: at what point should a source go directly to
#     quarantine instead of continuing through extraction? (Document the decision.)
