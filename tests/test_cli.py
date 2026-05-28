"""CLI integration tests (Spec 9).

Tests call command functions directly to avoid subprocess overhead and to allow
mocking extract_claims. The ingest path that touches a live LLM is mocked.
"""
from __future__ import annotations

import argparse
from pathlib import Path
from unittest.mock import patch

import pytest

from secure_wiki.__main__ import cmd_init, cmd_ingest, cmd_list, _source_id, _preview
from secure_wiki.models import Claim, ClaimStatus, SourceRef, TrustLevel

CORPUS = Path(__file__).parent / "injection_corpus"


def _args(**kwargs) -> argparse.Namespace:
    defaults = dict(source=None, trust=None, source_id=None, section="full", quarantine=False)
    return argparse.Namespace(**{**defaults, **kwargs})


def _make_claim(text: str = "test claim") -> Claim:
    return Claim(
        text=text,
        source=SourceRef(
            id="test",
            uri="https://attack.mitre.org/techniques/T1059",
            section="full",
            content_hash=SourceRef.compute_hash(text),
        ),
        trust_level=TrustLevel.TRUSTED,
        status=ClaimStatus.ACTIVE,
        gates_passed=["sanitizing", "provenance", "trust_tier", "adversarial_review", "consistency"],
    )


class TestCmdInit:
    def test_creates_wiki_repo(self, tmp_path, monkeypatch):
        monkeypatch.setenv("WIKI_DATA_PATH", str(tmp_path / "wiki"))
        cmd_init(_args())
        assert (tmp_path / "wiki" / ".git").exists()

    def test_idempotent(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setenv("WIKI_DATA_PATH", str(tmp_path / "wiki"))
        cmd_init(_args())
        cmd_init(_args())
        out = capsys.readouterr().out
        assert "already initialized" in out


class TestCmdList:
    def test_empty_store(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setenv("WIKI_DATA_PATH", str(tmp_path / "wiki"))
        cmd_list(_args(quarantine=False))
        assert "(none)" in capsys.readouterr().out

    def test_shows_committed_claim(self, tmp_path, monkeypatch, capsys):
        from secure_wiki.store.wiki_store import WikiStore
        monkeypatch.setenv("WIKI_DATA_PATH", str(tmp_path / "wiki"))
        store = WikiStore()
        store.save_claim(_make_claim("adversarial ML model attacks"))
        cmd_list(_args(quarantine=False))
        assert "adversarial ML" in capsys.readouterr().out

    def test_quarantine_flag(self, tmp_path, monkeypatch, capsys):
        from secure_wiki.store.wiki_store import WikiStore
        monkeypatch.setenv("WIKI_DATA_PATH", str(tmp_path / "wiki"))
        store = WikiStore()
        claim = _make_claim("bad claim")
        store.save_quarantined(claim)
        cmd_list(_args(quarantine=True))
        assert "Quarantined" in capsys.readouterr().out

    def test_trust_symbol_trusted(self, tmp_path, monkeypatch, capsys):
        from secure_wiki.store.wiki_store import WikiStore
        monkeypatch.setenv("WIKI_DATA_PATH", str(tmp_path / "wiki"))
        store = WikiStore()
        store.save_claim(_make_claim("trusted claim text"))
        cmd_list(_args())
        assert "[T]" in capsys.readouterr().out


class TestCmdIngest:
    def test_ingest_benign_file_commits(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setenv("WIKI_DATA_PATH", str(tmp_path / "wiki"))
        source_file = CORPUS / "08_benign_control.txt"
        extracted = [_make_claim("Adversarial ML attacks target model training data.")]

        with patch("secure_wiki.__main__.extract_claims", return_value=extracted), \
             patch("secure_wiki.gate.write_gate.review_write",
                   return_value=__import__("secure_wiki.review.adversarial", fromlist=["ReviewResult"]).ReviewResult(passed=True, reasons=[])):
            cmd_ingest(_args(source=str(source_file)))

        out = capsys.readouterr().out
        assert "COMMIT" in out
        assert "committed:   1" in out

    def test_ingest_suspicious_source_quarantines(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setenv("WIKI_DATA_PATH", str(tmp_path / "wiki"))
        source_file = CORPUS / "01_direct_instruction.txt"
        extracted = [_make_claim("some claim from suspicious source")]

        with patch("secure_wiki.__main__.extract_claims", return_value=extracted):
            cmd_ingest(_args(source=str(source_file)))

        out = capsys.readouterr().out
        assert "QUARANTINE" in out
        assert "quarantined: 1" in out

    def test_ingest_empty_extraction_exits_cleanly(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setenv("WIKI_DATA_PATH", str(tmp_path / "wiki"))
        source_file = CORPUS / "08_benign_control.txt"

        with patch("secure_wiki.__main__.extract_claims", return_value=[]), \
             pytest.raises(SystemExit) as exc_info:
            cmd_ingest(_args(source=str(source_file)))

        assert exc_info.value.code == 0
        assert "no claims extracted" in capsys.readouterr().out

    def test_ingest_manual_trust_override(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setenv("WIKI_DATA_PATH", str(tmp_path / "wiki"))
        source_file = CORPUS / "08_benign_control.txt"
        extracted = [_make_claim("some claim")]

        with patch("secure_wiki.__main__.extract_claims", return_value=extracted), \
             patch("secure_wiki.gate.write_gate.review_write",
                   return_value=__import__("secure_wiki.review.adversarial", fromlist=["ReviewResult"]).ReviewResult(passed=True, reasons=[])):
            cmd_ingest(_args(source=str(source_file), trust="trusted"))

        assert "manual override" in capsys.readouterr().out


class TestHelpers:
    def test_source_id_from_file(self):
        assert _source_id("path/to/document.txt") == "document"

    def test_source_id_from_url(self):
        sid = _source_id("https://attack.mitre.org/techniques/T1059")
        assert "T1059" in sid

    def test_preview_truncates(self):
        long = "word " * 30
        result = _preview(long, max_len=20)
        assert result.endswith("…")
        assert len(result) <= 22

    def test_preview_short_unchanged(self):
        assert _preview("short text") == "short text"
