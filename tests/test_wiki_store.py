"""Tests for the wiki store (Spec 4.6)."""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from secure_wiki.models import Claim, ClaimStatus, SourceRef, TrustLevel
from secure_wiki.store.wiki_store import WikiStore


def _make_claim(text: str = "test claim", trust: TrustLevel = TrustLevel.TRUSTED) -> Claim:
    return Claim(
        text=text,
        source=SourceRef(
            id="test-source",
            uri="https://attack.mitre.org/techniques/T1059",
            section="overview",
            content_hash=SourceRef.compute_hash(text),
        ),
        trust_level=trust,
        status=ClaimStatus.ACTIVE,
        gates_passed=["sanitizing", "provenance", "trust_tier", "adversarial_review", "consistency"],
    )


class TestInit:
    def test_creates_git_repo(self, tmp_path):
        store = WikiStore(root=tmp_path / "wiki")
        store.init()
        assert (tmp_path / "wiki" / ".git").exists()

    def test_creates_directory_structure(self, tmp_path):
        store = WikiStore(root=tmp_path / "wiki")
        store.init()
        assert (tmp_path / "wiki" / "pages").is_dir()
        assert (tmp_path / "wiki" / "quarantine").is_dir()

    def test_creates_trust_rules_yaml(self, tmp_path):
        store = WikiStore(root=tmp_path / "wiki")
        store.init()
        assert (tmp_path / "wiki" / "trust_rules.yaml").exists()

    def test_init_is_idempotent(self, tmp_path):
        store = WikiStore(root=tmp_path / "wiki")
        store.init()
        store.init()  # second call must not raise
        result = subprocess.run(
            ["git", "log", "--oneline"],
            cwd=tmp_path / "wiki",
            capture_output=True, text=True,
        )
        assert result.stdout.count("\n") == 1  # only the initial commit


class TestSaveClaim:
    def test_writes_markdown_file(self, tmp_path):
        store = WikiStore(root=tmp_path / "wiki")
        claim = _make_claim()
        path = store.save_claim(claim)
        assert path.exists()
        assert path.suffix == ".md"

    def test_file_contains_claim_text(self, tmp_path):
        store = WikiStore(root=tmp_path / "wiki")
        claim = _make_claim("adversarial ML attacks target model integrity")
        path = store.save_claim(claim)
        content = path.read_text()
        assert "adversarial ML attacks target model integrity" in content

    def test_file_contains_frontmatter(self, tmp_path):
        store = WikiStore(root=tmp_path / "wiki")
        claim = _make_claim()
        path = store.save_claim(claim)
        content = path.read_text()
        assert content.startswith("---\n")
        assert "trust_level:" in content
        assert "claim_id:" in content

    def test_creates_git_commit(self, tmp_path):
        store = WikiStore(root=tmp_path / "wiki")
        claim = _make_claim()
        store.save_claim(claim)
        result = subprocess.run(
            ["git", "log", "--oneline"],
            cwd=tmp_path / "wiki",
            capture_output=True, text=True,
        )
        assert "add" in result.stdout

    def test_commit_message_contains_source_uri(self, tmp_path):
        store = WikiStore(root=tmp_path / "wiki")
        claim = _make_claim()
        store.save_claim(claim)
        result = subprocess.run(
            ["git", "log", "--format=%s", "-1"],
            cwd=tmp_path / "wiki",
            capture_output=True, text=True,
        )
        assert "attack.mitre.org" in result.stdout

    def test_auto_inits_on_first_save(self, tmp_path):
        store = WikiStore(root=tmp_path / "wiki")
        store.save_claim(_make_claim())  # no explicit init()
        assert (tmp_path / "wiki" / ".git").exists()


class TestSaveQuarantined:
    def test_writes_to_quarantine_dir(self, tmp_path):
        store = WikiStore(root=tmp_path / "wiki")
        claim = _make_claim(trust=TrustLevel.UNTRUSTED)
        path = store.save_quarantined(claim, gate_detail="trust_tier: low-trust overwrite")
        assert "quarantine" in str(path)

    def test_sets_status_quarantined(self, tmp_path):
        store = WikiStore(root=tmp_path / "wiki")
        claim = _make_claim()
        store.save_quarantined(claim)
        assert claim.status == ClaimStatus.QUARANTINED

    def test_gate_detail_in_file(self, tmp_path):
        store = WikiStore(root=tmp_path / "wiki")
        claim = _make_claim()
        path = store.save_quarantined(claim, gate_detail="adversarial_review: rule manipulation")
        assert "adversarial_review" in path.read_text()


class TestLoadClaims:
    def test_roundtrip_active_claim(self, tmp_path):
        store = WikiStore(root=tmp_path / "wiki")
        original = _make_claim("roundtrip test claim")
        store.save_claim(original)
        loaded = store.load_claims()
        assert len(loaded) == 1
        assert loaded[0].text == "roundtrip test claim"
        assert loaded[0].claim_id == original.claim_id
        assert loaded[0].trust_level == TrustLevel.TRUSTED

    def test_load_preserves_gates_passed(self, tmp_path):
        store = WikiStore(root=tmp_path / "wiki")
        claim = _make_claim()
        store.save_claim(claim)
        loaded = store.load_claims()[0]
        assert "sanitizing" in loaded.gates_passed
        assert "consistency" in loaded.gates_passed

    def test_multiple_claims(self, tmp_path):
        store = WikiStore(root=tmp_path / "wiki")
        for i in range(3):
            store.save_claim(_make_claim(f"claim number {i}"))
        assert len(store.load_claims()) == 3

    def test_load_quarantined(self, tmp_path):
        store = WikiStore(root=tmp_path / "wiki")
        claim = _make_claim(trust=TrustLevel.UNTRUSTED)
        store.save_quarantined(claim)
        quarantined = store.load_quarantined()
        assert len(quarantined) == 1
        assert quarantined[0].status == ClaimStatus.QUARANTINED

    def test_pages_not_mixed_with_quarantine(self, tmp_path):
        store = WikiStore(root=tmp_path / "wiki")
        store.save_claim(_make_claim("active claim"))
        store.save_quarantined(_make_claim("bad claim", trust=TrustLevel.UNTRUSTED))
        assert len(store.load_claims()) == 1
        assert len(store.load_quarantined()) == 1
