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


_MAX_RETRIES = 2


def review_write(
    proposed: list[Claim],
    existing_high_trust: list[Claim] | None = None,
) -> ReviewResult:
    """Review a proposed write operation (Spec 4.4).

    existing_high_trust: active high-trust claims checked against for
    unjustified overwriting.

    Retries up to _MAX_RETRIES times on unparseable responses before
    failing closed — guards against flaky model output without weakening
    security (a deliberate block still blocks on the first attempt).
    """
    client = get_review_client()

    proposed_lines = "\n".join(
        f"- [{c.trust_level.value}] {c.text}" for c in proposed
    )
    user = f"PROPOSED CLAIMS:\n{proposed_lines}"

    if existing_high_trust:
        existing_lines = "\n".join(f"- {c.text}" for c in existing_high_trust)
        user += f"\n\nEXISTING HIGH-TRUST CLAIMS:\n{existing_lines}"

    last_error = "review model returned unparseable response"
    for attempt in range(1, _MAX_RETRIES + 2):
        raw = client.complete(REVIEW_SYSTEM_PROMPT, user).text
        try:
            result = json.loads(extract_json_object(raw))
            passed = result.get("verdict") == "pass"
            reasons = result.get("reasons", [])
            return ReviewResult(passed=passed, reasons=reasons)
        except json.JSONDecodeError:
            preview = raw[:80].replace("\n", " ")
            last_error = f"review model returned unparseable response (attempt {attempt}): {preview!r}"

    return ReviewResult(passed=False, reasons=[last_error])
