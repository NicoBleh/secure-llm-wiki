"""Write-Gate — erweitertes Lint, bündelt alle Prüfungen (Spec 4.5).

Commit nur, wenn ALLE Gates bestanden sind. Konflikte zu hoch-vertrauten
bestehenden Aussagen werden NICHT automatisch aufgelöst, sondern eskaliert
(Mensch-im-Loop, Spec 4.5).

Status: STUB mit definierter Orchestrierungs-Reihenfolge.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from ..models import Claim, ClaimStatus


class GateDecision(str, Enum):
    COMMIT = "commit"
    QUARANTINE = "quarantine"
    ESCALATE = "escalate"  # Konflikt → Mensch-im-Loop


@dataclass
class GateOutcome:
    decision: GateDecision
    claim: Claim
    detail: str


def run_write_gate(claim: Claim) -> GateOutcome:
    """Führt alle Gates der Reihe nach aus (Spec 4.5).

    Reihenfolge (alle müssen bestehen):
      1. Sanitizing bestanden        (Flag aus Ingestion prüfen)
      2. Provenance vollständig      (source + hash + trust_level gesetzt)
      3. Trust-Tier geprüft          (Low-Trust überschreibt nichts)
      4. Adversarial-Review bestanden
      5. Konsistenz-Check gegen bestehende Claims
    Konflikt mit hoch-vertrautem Bestand → ESCALATE, nicht automatisch lösen.
    """
    raise NotImplementedError(
        "TODO(claude-code): Gates 1-5 in dieser Reihenfolge ausführen. "
        "Bei Bestehen claim.status=ACTIVE und gates_passed füllen, dann COMMIT. "
        "Bei Low-Trust-Overwrite oder Review-Block → QUARANTINE. "
        "Bei Widerspruch zu hoch-vertrautem Bestand → ESCALATE (Spec 4.5)."
    )
