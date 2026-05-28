"""Zentrale Datenstrukturen für das Secure LLM-Wiki.

Dieses Modul definiert das Provenance-Schema (siehe Spec Abschnitt 6) als
Single Source of Truth. Alle Pipeline-Schichten importieren von hier.

Status: SKELETT. Felder und Validierung sind vollständig; Persistenz-Helfer
sind als TODO markiert und von Claude Code zu implementieren.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
import uuid


class TrustLevel(str, Enum):
    """Vertrauensstufe einer Quelle bzw. eines Claims (Spec 4.3)."""
    TRUSTED = "trusted"          # vom Nutzer kuratiert/verifiziert
    SEMI_TRUSTED = "semi-trusted"  # etabliert, aber nicht einzeln geprüft
    UNTRUSTED = "untrusted"      # beliebiger Web-Fund, agentisch gecrawlt

    @classmethod
    def weakest(cls, levels: list["TrustLevel"]) -> "TrustLevel":
        """Propagierungsregel: ein Claim erbt das SCHWÄCHSTE Level (Spec 4.3)."""
        order = [cls.TRUSTED, cls.SEMI_TRUSTED, cls.UNTRUSTED]
        return max(levels, key=order.index) if levels else cls.UNTRUSTED


class ClaimStatus(str, Enum):
    """Lebenszyklus-Status eines Claims (Spec 6)."""
    ACTIVE = "active"          # committet, im Wiki sichtbar
    PENDING = "pending"        # wartet auf Review/Bestätigung
    QUARANTINED = "quarantined"  # Review nicht bestanden
    SUPERSEDED = "superseded"  # durch neueren Claim ersetzt


@dataclass
class SourceRef:
    """Herkunftsreferenz eines Claims (Spec 6)."""
    id: str
    uri: str
    section: str
    content_hash: str  # sha256 des normalisierten Originalabschnitts

    @staticmethod
    def compute_hash(original_text: str) -> str:
        """SHA-256 über den normalisierten Originaltext (Spec 7)."""
        normalized = " ".join(original_text.split())
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


@dataclass
class Claim:
    """Eine atomare, prüfbare Aussage mit vollständiger Provenance (Spec 6).

    Dies ist die zentrale Datenstruktur des gesamten Systems. Jede Pipeline-
    Schicht reichert sie an, niemals wird Provenance entfernt.
    """
    text: str
    source: SourceRef
    trust_level: TrustLevel
    claim_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    ingested_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    status: ClaimStatus = ClaimStatus.PENDING
    gates_passed: list[str] = field(default_factory=list)
    supersedes: Optional[str] = None
    review_notes: Optional[str] = None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["trust_level"] = self.trust_level.value
        d["status"] = self.status.value
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Claim":
        source = SourceRef(
            id=d["source"]["id"],
            uri=d["source"]["uri"],
            section=d["source"]["section"],
            content_hash=d["source"]["content_hash"],
        )
        return cls(
            text=d["text"],
            source=source,
            trust_level=TrustLevel(d["trust_level"]),
            claim_id=d["claim_id"],
            ingested_at=d["ingested_at"],
            status=ClaimStatus(d["status"]),
            gates_passed=d.get("gates_passed", []),
            supersedes=d.get("supersedes"),
            review_notes=d.get("review_notes"),
        )
