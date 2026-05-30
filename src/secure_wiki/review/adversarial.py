"""Adversarial Review — machine four-eyes principle (Spec 4.4).

An INDEPENDENT review model (separate context, separate system instruction,
ideally a different model) checks every proposed write operation for
MANIPULATION — not for factual correctness.

Independence: REVIEW_MODEL should differ from EXTRACTION_MODEL so a jailbreak
cannot compromise both the extractor and the reviewer simultaneously.
See secure_wiki/prompts.py for the prompt text and its security rationale.
"""
from __future__ import annotations

import json
from dataclasses import dataclass

from ..llm_client import extract_json_object, get_review_client
from ..models import Claim
from ..prompts import REVIEW_SYSTEM_PROMPT


@dataclass
class ReviewResult:
    passed: bool
    reasons: list[str]


def review_write(
    proposed: list[Claim],
    existing_high_trust: list[Claim] | None = None,
) -> ReviewResult:
    """Review a proposed write operation (Spec 4.4).

    existing_high_trust: active high-trust claims checked against for
    unjustified overwriting.

    Fail-closed: blocks if the model response cannot be parsed.
    """
    client = get_review_client()

    proposed_lines = "\n".join(
        f"- [{c.trust_level.value}] {c.text}" for c in proposed
    )
    user = f"PROPOSED CLAIMS:\n{proposed_lines}"

    if existing_high_trust:
        existing_lines = "\n".join(f"- {c.text}" for c in existing_high_trust)
        user += f"\n\nEXISTING HIGH-TRUST CLAIMS:\n{existing_lines}"

    raw = client.complete(REVIEW_SYSTEM_PROMPT, user).text

    try:
        result = json.loads(extract_json_object(raw))
        passed = result.get("verdict") == "pass"
        reasons = result.get("reasons", [])
    except json.JSONDecodeError:
        return ReviewResult(passed=False, reasons=["review model returned unparseable response"])

    return ReviewResult(passed=passed, reasons=reasons)
