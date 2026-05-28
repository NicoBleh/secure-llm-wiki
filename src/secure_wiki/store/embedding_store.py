"""Embedding store — persists claim embeddings alongside the wiki data repo.

Embeddings live in wiki_data/embeddings/<claim_id>.json so they are
co-located with the claim files but kept separate from the Markdown pages.
The directory is not git-tracked (embeddings are reproducible from claim text).
"""
from __future__ import annotations

import json
from pathlib import Path

from ..store.wiki_store import WikiStore


def cosine_similarity(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    mag_a = sum(x * x for x in a) ** 0.5
    mag_b = sum(x * x for x in b) ** 0.5
    if mag_a == 0.0 or mag_b == 0.0:
        return 0.0
    return dot / (mag_a * mag_b)


class EmbeddingStore:
    """Read/write embeddings keyed by claim_id."""

    def __init__(self, wiki_store: WikiStore | None = None) -> None:
        store = wiki_store or WikiStore()
        self._dir = store.root / "embeddings"
        self._dir.mkdir(parents=True, exist_ok=True)

    def save(self, claim_id: str, embedding: list[float]) -> None:
        path = self._dir / f"{claim_id}.json"
        path.write_text(json.dumps({"claim_id": claim_id, "embedding": embedding}), encoding="utf-8")

    def load_all(self) -> dict[str, list[float]]:
        result: dict[str, list[float]] = {}
        for path in self._dir.glob("*.json"):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                result[data["claim_id"]] = data["embedding"]
            except Exception:
                pass
        return result

    def delete(self, claim_id: str) -> None:
        path = self._dir / f"{claim_id}.json"
        if path.exists():
            path.unlink()
