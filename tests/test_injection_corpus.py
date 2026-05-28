"""Regressionssuite gegen den Injection-Korpus (Spec 8).

Lädt das Manifest und prüft, dass jeder Angriff an der ERWARTETEN Gate
gestoppt wird und der Kontrollfall sauber durchläuft. Diese Tests sichern die
Härtung gegen spätere Regressionen ab.

Status: Sanitizing-Ebene ist bereits testbar (TestSanitizerLayer läuft grün).
Die Volltest gegen die komplette Pipeline ist TODO, sobald Review + Write-Gate
implementiert sind.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from secure_wiki.ingestion.sanitizer import sanitize

CORPUS = Path(__file__).parent / "injection_corpus"
MANIFEST = json.loads((CORPUS / "manifest.json").read_text())
CASES = MANIFEST["cases"]


def _load(case) -> str:
    return (CORPUS / case["file"]).read_text(encoding="utf-8")


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
class TestSanitizerLayer:
    """Prüft die Sanitizing-Stufe gegen jeden Korpus-Fall."""

    def test_sanitizing_matches_manifest(self, case):
        report = sanitize(_load(case))
        flag_types = {f.split(":")[0] for f in report.flags}

        if case["expected_stop_gate"] == "sanitizing":
            # Muss hier gestoppt werden: erwartete Flags müssen auftreten.
            for expected in case["expected_flags"]:
                assert expected in flag_types, (
                    f"{case['id']}: erwartetes Flag '{expected}' fehlt "
                    f"(gefunden: {flag_types})"
                )
        elif case["expected_stop_gate"] is None:
            # Kontrollfall: Sanitizer darf NICHT anschlagen.
            assert not report.is_suspicious, (
                f"{case['id']} ist Kontrollfall, wurde aber geflaggt: "
                f"{report.flags}"
            )
        # Fälle für spätere Gates dürfen den Sanitizer passieren — kein Assert.


# TODO(claude-code): TestFullPipeline ergänzen, sobald review + write_gate
#   stehen. Pro Fall prüfen, dass decision/Quarantäne genau an
#   case['expected_stop_gate'] erfolgt (Spec 8, Regressionssuite).
