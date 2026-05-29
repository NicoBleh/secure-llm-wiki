"""Claim extraction from sanitized source text (Spec 4.2).

Calls the extraction LLM with nonce-delimited input and parses the structured
JSON response into Claim objects with full provenance.

Fail-closed: if the model response cannot be parsed, returns an empty list so
the write gate quarantines rather than silently passing bad output.
"""
from __future__ import annotations

import json

from ..prompts import build_extraction_prompt
from ..llm_client import get_extraction_client, strip_fences
from ..models import Claim, ClaimStatus, SourceRef, TrustLevel


def _parse_items(raw: str) -> list[dict]:
    """Parse model output that may be a single JSON array or multiple arrays.

    Some models return one array per line instead of a single top-level array
    despite the system prompt. This handles both forms.
    """
    cleaned = strip_fences(raw)

    # Fast path: well-formed single array
    try:
        result = json.loads(cleaned)
        if isinstance(result, list):
            return result
    except json.JSONDecodeError:
        pass

    # Fallback: parse each non-empty line independently and flatten
    items: list[dict] = []
    for line in cleaned.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            parsed = json.loads(line)
            if isinstance(parsed, list):
                items.extend(parsed)
            elif isinstance(parsed, dict):
                items.append(parsed)
        except json.JSONDecodeError:
            continue
    return items


def extract_claims(
    source_text: str,
    source_ref: SourceRef,
    trust_level: TrustLevel,
) -> list[Claim]:
    """Extract atomic claims from source_text via the extraction LLM."""
    client = get_extraction_client()
    system, user, _nonce = build_extraction_prompt(source_text)
    raw = client.complete(system, user)

    claims = []
    for item in _parse_items(raw):
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
