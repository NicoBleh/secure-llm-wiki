"""Write-Gate — bundles all pipeline checks before a wiki commit (Spec 4.5).

A claim is committed only when ALL five gates pass. Conflicts with established
high-trust content are never auto-resolved — they escalate to human review.

Gates run in sequence (fail-fast):
  1. Sanitizing passed       — no obfuscation flags from ingestion
  2. Provenance complete     — source.id, uri, content_hash all set
  3. Trust-tier              — untrusted claim cannot overwrite high-trust content
  4. Adversarial review      — independent model found no manipulation
  5. Consistency             — embedding similarity against existing claims:
                               >= duplicate_threshold  → quarantine (duplicate)
                               >= conflict_threshold   → escalate (human review)
                               (falls back to section heuristic if no embeddings)
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from ..ingestion.sanitizer import SanitizeReport
from ..models import Claim, ClaimStatus, TrustLevel
from ..review.adversarial import review_write
from ..store.embedding_store import cosine_similarity

# Thresholds — overridable via trust_rules.yaml (loaded by caller)
DEFAULT_DUPLICATE_THRESHOLD = 0.95
DEFAULT_CONFLICT_THRESHOLD = 0.85


class GateDecision(str, Enum):
    COMMIT = "commit"
    QUARANTINE = "quarantine"
    ESCALATE = "escalate"  # conflict → human-in-the-loop


@dataclass
class GateOutcome:
    decision: GateDecision
    claim: Claim
    detail: str


def run_write_gate(
    claim: Claim,
    sanitize_report: SanitizeReport,
    existing_claims: list[Claim] | None = None,
    new_embedding: list[float] | None = None,
    existing_embeddings: dict[str, list[float]] | None = None,
    duplicate_threshold: float = DEFAULT_DUPLICATE_THRESHOLD,
    conflict_threshold: float = DEFAULT_CONFLICT_THRESHOLD,
) -> GateOutcome:
    """Run all gates in sequence and return a commit/quarantine/escalate decision.

    existing_claims: active wiki claims used for trust-tier and consistency checks.
    """
    existing = existing_claims or []
    existing_trusted = [
        c for c in existing
        if c.trust_level == TrustLevel.TRUSTED and c.status == ClaimStatus.ACTIVE
    ]

    # Gate 1: sanitizing
    if sanitize_report.flags:
        return GateOutcome(
            decision=GateDecision.QUARANTINE,
            claim=claim,
            detail=f"sanitizing: {', '.join(sanitize_report.flags)}",
        )
    claim.gates_passed.append("sanitizing")

    # Gate 2: provenance complete
    missing = [
        name for name, val in [
            ("source.id", claim.source.id),
            ("source.uri", claim.source.uri),
            ("source.content_hash", claim.source.content_hash),
        ]
        if not val
    ]
    if missing:
        return GateOutcome(
            decision=GateDecision.QUARANTINE,
            claim=claim,
            detail=f"provenance incomplete: {', '.join(missing)}",
        )
    claim.gates_passed.append("provenance")

    # Gate 3: trust-tier — untrusted source cannot overwrite established content
    if claim.trust_level == TrustLevel.UNTRUSTED and existing_trusted:
        return GateOutcome(
            decision=GateDecision.QUARANTINE,
            claim=claim,
            detail=(
                f"trust_tier: untrusted claim would overwrite "
                f"{len(existing_trusted)} established high-trust claim(s)"
            ),
        )
    claim.gates_passed.append("trust_tier")

    # Gate 4: adversarial review
    review = review_write(
        proposed=[claim],
        existing_high_trust=existing_trusted or None,
    )
    if not review.passed:
        claim.review_notes = "; ".join(review.reasons)
        return GateOutcome(
            decision=GateDecision.QUARANTINE,
            claim=claim,
            detail=f"adversarial_review: {claim.review_notes}",
        )
    claim.gates_passed.append("adversarial_review")

    # Gate 5: consistency — embedding-based duplicate/conflict detection
    if new_embedding is not None and existing_embeddings:
        best_id, best_score = max(
            existing_embeddings.items(),
            key=lambda kv: cosine_similarity(new_embedding, kv[1]),
            default=(None, 0.0),
        )
        if best_id is not None:
            score = cosine_similarity(new_embedding, existing_embeddings[best_id])
            if score >= duplicate_threshold:
                return GateOutcome(
                    decision=GateDecision.QUARANTINE,
                    claim=claim,
                    detail=f"consistency: duplicate of {best_id[:8]} (similarity={score:.3f})",
                )
            if score >= conflict_threshold:
                return GateOutcome(
                    decision=GateDecision.ESCALATE,
                    claim=claim,
                    detail=(
                        f"consistency: semantically similar to {best_id[:8]} "
                        f"(similarity={score:.3f}) — human review required"
                    ),
                )
    else:
        # Fallback heuristic when embeddings are unavailable
        conflicts = [
            c for c in existing_trusted
            if c.source.section == claim.source.section and c.source.id != claim.source.id
        ]
        if conflicts:
            return GateOutcome(
                decision=GateDecision.ESCALATE,
                claim=claim,
                detail=(
                    f"consistency: contradicts {len(conflicts)} high-trust claim(s) "
                    "in the same section — human review required"
                ),
            )
    claim.gates_passed.append("consistency")

    claim.status = ClaimStatus.ACTIVE
    return GateOutcome(
        decision=GateDecision.COMMIT,
        claim=claim,
        detail="all gates passed",
    )
