"""Write-Gate — bundles all pipeline checks before a wiki commit (Spec 4.5).

A claim is committed only when ALL five gates pass. Conflicts with established
high-trust content are never auto-resolved — they escalate to human review.

Gates run in sequence (fail-fast):
  1. Sanitizing passed       — no obfuscation flags from ingestion
  2. Provenance complete     — source.id, uri, content_hash all set
  3. Trust-tier              — untrusted claim cannot overwrite high-trust content
  4. Adversarial review      — independent model found no manipulation
  5. Consistency             — no contradiction with existing high-trust claims
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from ..ingestion.sanitizer import SanitizeReport
from ..models import Claim, ClaimStatus, TrustLevel
from ..review.adversarial import review_write


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

    # Gate 5: consistency — same section, different source = potential contradiction
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
