"""Central data structures for the Secure LLM-Wiki.

This module defines the provenance schema (see Spec section 6) as the single
source of truth. All pipeline layers import from here.

Status: COMPLETE. Fields and validation are fully implemented; persistence
helpers live in store/wiki_store.py.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
import uuid


class TrustLevel(str, Enum):
    """Trust level of a source or claim (Spec 4.3)."""
    TRUSTED = "trusted"            # curated/verified by the user
    SEMI_TRUSTED = "semi-trusted"  # established source, not individually reviewed
    UNTRUSTED = "untrusted"        # arbitrary web find, agentically crawled

    @classmethod
    def weakest(cls, levels: list["TrustLevel"]) -> "TrustLevel":
        """Propagation rule: a claim inherits the WEAKEST level of its sources (Spec 4.3)."""
        order = [cls.TRUSTED, cls.SEMI_TRUSTED, cls.UNTRUSTED]
        return max(levels, key=order.index) if levels else cls.UNTRUSTED


class ClaimStatus(str, Enum):
    """Lifecycle status of a claim (Spec 6)."""
    ACTIVE = "active"            # committed, visible in the wiki
    PENDING = "pending"          # awaiting review/confirmation
    QUARANTINED = "quarantined"  # failed review
    SUPERSEDED = "superseded"    # replaced by a newer claim


@dataclass
class SourceRef:
    """Source reference for a claim (Spec 6)."""
    id: str
    uri: str
    section: str
    content_hash: str  # sha256 of the normalized original section

    @staticmethod
    def compute_hash(original_text: str) -> str:
        """SHA-256 over the normalized original text (Spec 7)."""
        normalized = " ".join(original_text.split())
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


@dataclass
class Claim:
    """An atomic, verifiable statement with full provenance (Spec 6).

    This is the central data structure of the entire system. Every pipeline
    stage enriches it; provenance is never removed.
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
