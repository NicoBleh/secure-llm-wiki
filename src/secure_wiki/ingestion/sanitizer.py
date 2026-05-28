"""Sanitizing-Pass der Ingestion-Schicht (Spec 4.1).

Erkennt und flaggt typische Injection-Verschleierungsvektoren, BEVOR Quelltext
ein Modell erreicht. Geflaggte Inhalte werden NICHT still verworfen, sondern
protokolliert (forensisch relevant, Spec 4.1).

Status: TEILIMPLEMENTIERT. Die Erkennungsmuster sind funktionsfähig; die
Integration ins Logging und die Anbindung an die Pipeline sind TODO.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field


# Unsichtbare / gefährliche Unicode-Codepoints (Zero-Width, Bidi-Override).
_INVISIBLE_CODEPOINTS = {
    "\u200b", "\u200c", "\u200d", "\ufeff",  # zero-width space/joiner/BOM
    "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",  # bidi overrides
    "\u2066", "\u2067", "\u2068", "\u2069",  # isolates
}

# Heuristische Instruktionsmuster (Spec 4.1). Bewusst breit; false positives
# werden geflaggt, nicht entfernt — die Entscheidung trifft eine spätere Stufe.
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
    """Ergebnis eines Sanitizing-Passes."""
    cleaned_text: str
    flags: list[str] = field(default_factory=list)

    @property
    def is_suspicious(self) -> bool:
        return bool(self.flags)


def sanitize(text: str) -> SanitizeReport:
    """Normalisiert Text und flaggt Verschleierungsvektoren (Spec 4.1).

    Gibt den bereinigten Text plus eine Liste von Flags zurück. Entfernt
    unsichtbare Zeichen, behält aber sichtbare verdächtige Muster bei und
    flaggt sie nur — die Quelle bleibt für die spätere Verarbeitung lesbar.
    """
    flags: list[str] = []

    # 1) Unsichtbare Codepoints entfernen + flaggen.
    found_invisible = {c for c in text if c in _INVISIBLE_CODEPOINTS}
    if found_invisible:
        flags.append(f"invisible_chars:{len(found_invisible)}")
    cleaned = "".join(c for c in text if c not in _INVISIBLE_CODEPOINTS)

    # 2) Sonstige Steuerzeichen (außer Whitespace) flaggen.
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


# TODO(claude-code):
#   - Flags an ein strukturiertes Audit-Log anbinden (Spec 4.1, "protokolliert").
#   - Schwellenwert-Policy definieren: ab wann geht eine Quelle direkt in
#     Quarantäne statt durch Extraction? (Designentscheidung dokumentieren.)
