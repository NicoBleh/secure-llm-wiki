"""Claim extraction from sanitized source text (Spec 4.2).

Calls the extraction LLM with nonce-delimited input and parses the structured
JSON response into Claim objects with full provenance.

Fail-closed: if the model response cannot be parsed, returns an empty list so
the write gate quarantines rather than silently passing bad output.
"""
from __future__ import annotations

import json

from ..prompts import build_extraction_prompt
from ..llm_client import UsageInfo, get_extraction_client, strip_fences
from ..models import Claim, ClaimStatus, SourceRef, TrustLevel


def _parse_items(raw: str) -> tuple[list[dict], str | None]:
    """Parse model output into a list of claim dicts.

    Handles three formats models may return despite the system prompt:
      1. Envelope object  {"nonce": "...", "claims": [...]}  (current prompt)
      2. Plain array      [{...}, {...}]                     (legacy)
      3. One JSON value per line                             (some Ollama models)

    Returns (items, parse_error) where parse_error is a short diagnostic string
    when nothing could be parsed, or None on success.
    """
    cleaned = strip_fences(raw)

    try:
        parsed = json.loads(cleaned)
        # Current format: envelope object with a "claims" key
        if isinstance(parsed, dict) and "claims" in parsed:
            items = parsed["claims"]
            return (items if isinstance(items, list) else []), None
        # Legacy format: bare array
        if isinstance(parsed, list):
            return parsed, None
    except json.JSONDecodeError:
        pass

    # Fallback: parse each non-empty line independently and flatten
    items: list[dict] = []
    for line in cleaned.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict) and "claims" in obj:
                claims = obj["claims"]
                if isinstance(claims, list):
                    items.extend(claims)
            elif isinstance(obj, list):
                items.extend(obj)
            elif isinstance(obj, dict):
                items.append(obj)
        except json.JSONDecodeError:
            continue

    if not items:
        preview = cleaned[:120].replace("\n", " ")
        return [], f"unparseable response: {preview!r}"
    return items, None


def extract_claims(
    source_text: str,
    source_ref: SourceRef,
    trust_level: TrustLevel,
) -> tuple[list[Claim], UsageInfo, str | None]:
    """Extract atomic claims from source_text via the extraction LLM.

    Returns (claims, usage, parse_error). parse_error is None on success or a
    short diagnostic string when the model response could not be parsed.
    """
    client = get_extraction_client()
    system, user, _nonce = build_extraction_prompt(source_text)
    result = client.complete(system, user)

    items, parse_error = _parse_items(result.text)
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
    return claims, result.usage, parse_error
