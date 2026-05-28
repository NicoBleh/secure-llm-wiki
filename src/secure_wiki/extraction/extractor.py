"""Claim extraction from sanitized source text (Spec 4.2).

Calls the extraction LLM with nonce-delimited input and parses the structured
JSON response into Claim objects with full provenance.

Fail-closed: if the model response cannot be parsed, returns an empty list so
the write gate quarantines rather than silently passing bad output.
"""
from __future__ import annotations

import json

from ..ingestion.prompts import build_extraction_prompt
from ..llm_client import get_extraction_client, strip_fences
from ..models import Claim, ClaimStatus, SourceRef, TrustLevel


def extract_claims(
    source_text: str,
    source_ref: SourceRef,
    trust_level: TrustLevel,
) -> list[Claim]:
    """Extract atomic claims from source_text via the extraction LLM."""
    client = get_extraction_client()
    system, user, _nonce = build_extraction_prompt(source_text)
    raw = client.complete(system, user)

    try:
        items = json.loads(strip_fences(raw))
    except json.JSONDecodeError:
        return []

    claims = []
    for item in items:
        if not isinstance(item, dict) or "text" not in item:
            continue
        claims.append(
            Claim(
                text=item["text"],
                source=source_ref,
                trust_level=trust_level,
                status=ClaimStatus.PENDING,
            )
        )
    return claims
