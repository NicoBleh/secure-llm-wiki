"""Wiki store — persists claims as Markdown + YAML frontmatter under a
dedicated git repository separate from the project source repo (Spec 4.6).

Every write (commit or quarantine) produces a git commit in the wiki repo,
referencing the source URI in the message. This gives a full forensic audit
trail: git log shows every ingestion event, git diff shows what changed,
git revert rolls back a poisoned claim.

Directory layout of the wiki repo:
  <root>/
    pages/       — committed (ACTIVE) claims
    quarantine/  — QUARANTINED / PENDING claims
    trust_rules.yaml  — user-editable trust rules (see trust/tiering.py)

The root defaults to ./wiki_data/ or $WIKI_DATA_PATH if set.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import yaml

from ..models import Claim, ClaimStatus

_TRUST_RULES_TEMPLATE = """\
# Trust rules for this wiki instance.
# Rules are matched top-to-bottom against the source URI; first match wins.
# See project README for built-in defaults and documentation.
#
# Example:
#   rules:
#     - pattern: "internal\\.corp\\.example\\.com"
#       level: trusted
#       comment: "Internal knowledge base"

rules: []

# Gate 5 similarity thresholds (embedding-based duplicate/conflict detection).
# duplicate_threshold: cosine similarity >= this → quarantine as duplicate
# conflict_threshold:  cosine similarity >= this → escalate for human review
similarity:
  duplicate_threshold: 0.95
  conflict_threshold: 0.85
"""

_GIT_ENV = {
    **os.environ,
    "GIT_AUTHOR_NAME": "secure-llm-wiki",
    "GIT_AUTHOR_EMAIL": "wiki@local",
    "GIT_COMMITTER_NAME": "secure-llm-wiki",
    "GIT_COMMITTER_EMAIL": "wiki@local",
}


def _git(args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        env=_GIT_ENV,
    )


def _serialize(claim: Claim, gate_detail: str = "") -> str:
    """Render claim as YAML-frontmatter Markdown."""
    d = claim.to_dict()
    frontmatter = yaml.dump(d, default_flow_style=False, allow_unicode=True, sort_keys=True)
    body = claim.text
    if gate_detail:
        body += f"\n\n> Gate decision: {gate_detail}"
    return f"---\n{frontmatter}---\n\n{body}\n"


def _deserialize(path: Path) -> Claim:
    """Parse a frontmatter Markdown file back into a Claim."""
    text = path.read_text(encoding="utf-8")
    parts = text.split("---\n", 2)
    if len(parts) < 3:
        raise ValueError(f"missing frontmatter in {path}")
    raw = yaml.safe_load(parts[1])
    return Claim.from_dict(raw)


class WikiStore:
    """Manages the wiki data repository.

    Call init() once (or let the first save call do it automatically).
    """

    def __init__(self, root: Path | None = None) -> None:
        self.root = root or Path(os.environ.get("WIKI_DATA_PATH", "wiki_data"))
        self.pages = self.root / "pages"
        self.quarantine = self.root / "quarantine"

    # ------------------------------------------------------------------
    # Initialisation
    # ------------------------------------------------------------------

    def init(self) -> None:
        """Create the wiki repo from scratch if it doesn't exist."""
        self.pages.mkdir(parents=True, exist_ok=True)
        self.quarantine.mkdir(parents=True, exist_ok=True)

        if (self.root / ".git").exists():
            return

        _git(["init"], self.root)
        _git(["config", "user.name", "secure-llm-wiki"], self.root)
        _git(["config", "user.email", "wiki@local"], self.root)

        rules_file = self.root / "trust_rules.yaml"
        if not rules_file.exists():
            rules_file.write_text(_TRUST_RULES_TEMPLATE, encoding="utf-8")

        _git(["add", "."], self.root)
        _git(["commit", "-m", "Initialize wiki store"], self.root)

    # ------------------------------------------------------------------
    # Writes
    # ------------------------------------------------------------------

    def save_claim(self, claim: Claim, gate_detail: str = "") -> Path:
        """Write an ACTIVE claim to pages/ and commit."""
        self._ensure_init()
        path = self.pages / f"{claim.claim_id}.md"
        path.write_text(_serialize(claim, gate_detail), encoding="utf-8")
        msg = f"add {claim.claim_id[:8]} [{claim.trust_level.value}] from {claim.source.uri}"
        self._commit(path, msg)
        return path

    def save_quarantined(self, claim: Claim, gate_detail: str = "") -> Path:
        """Write a QUARANTINED claim to quarantine/ and commit."""
        self._ensure_init()
        claim.status = ClaimStatus.QUARANTINED
        path = self.quarantine / f"{claim.claim_id}.md"
        path.write_text(_serialize(claim, gate_detail), encoding="utf-8")
        reason = gate_detail[:72] if gate_detail else "gate failed"
        msg = f"quarantine {claim.claim_id[:8]} from {claim.source.uri}: {reason}"
        self._commit(path, msg)
        return path

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    def load_claims(self, status: ClaimStatus | None = ClaimStatus.ACTIVE) -> list[Claim]:
        """Load claims from pages/, optionally filtered by status."""
        return self._load_dir(self.pages, status)

    def load_quarantined(self) -> list[Claim]:
        """Load all claims from quarantine/."""
        return self._load_dir(self.quarantine, status=None)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _ensure_init(self) -> None:
        if not (self.root / ".git").exists():
            self.init()

    def _commit(self, path: Path, message: str) -> None:
        rel = str(path.relative_to(self.root))
        _git(["add", rel], self.root)
        _git(["commit", "-m", message], self.root)

    def _load_dir(self, directory: Path, status: ClaimStatus | None) -> list[Claim]:
        if not directory.exists():
            return []
        claims = []
        for path in sorted(directory.glob("*.md")):
            try:
                claim = _deserialize(path)
                if status is None or claim.status == status:
                    claims.append(claim)
            except Exception:
                pass
        return claims
