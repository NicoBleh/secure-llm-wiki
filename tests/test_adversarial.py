"""Tests for adversarial review — Fix 1 regression guards (Spec 4.4).

Verifies:
  - build_review_prompt uses the nonce builder correctly (no literal {nonce})
  - review_write fails closed on nonce mismatch
  - review_write fails closed on unparseable model response
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from secure_wiki.models import Claim, ClaimStatus, SourceRef, TrustLevel
from secure_wiki.prompts import build_review_prompt
from secure_wiki.review.adversarial import ReviewResult, review_write


def _make_claim(text: str = "some extracted claim") -> Claim:
    return Claim(
        text=text,
        source=SourceRef(
            id="test-src",
            uri="https://example.com/doc",
            section="overview",
            content_hash=SourceRef.compute_hash(text),
        ),
        trust_level=TrustLevel.SEMI_TRUSTED,
        status=ClaimStatus.PENDING,
    )


class TestBuildReviewPrompt:
    def test_no_literal_nonce_placeholder_in_system(self):
        """After building, no un-filled {nonce} must remain in the system prompt."""
        claims = [_make_claim()]
        system, _user, _nonce = build_review_prompt(claims, source_text="source text")
        assert "{nonce}" not in system

    def test_user_contains_proposed_nonce_block(self):
        claims = [_make_claim()]
        _system, user, nonce = build_review_prompt(claims, source_text="source text")
        assert f"<proposed-{nonce}>" in user
        assert f"</proposed-{nonce}>" in user

    def test_user_contains_source_nonce_block(self):
        claims = [_make_claim()]
        _system, user, nonce = build_review_prompt(claims, source_text="source text")
        assert f"<source-{nonce}>" in user
        assert f"</source-{nonce}>" in user

    def test_nonce_unique_per_call(self):
        claims = [_make_claim()]
        _, _, nonce1 = build_review_prompt(claims, source_text="text")
        _, _, nonce2 = build_review_prompt(claims, source_text="text")
        assert nonce1 != nonce2


class TestReviewWriteFailClosed:
    def test_nonce_mismatch_blocks(self):
        """Reviewer returns valid JSON but wrong nonce → must fail closed."""
        claims = [_make_claim()]
        mock_result = MagicMock()
        mock_result.text = json.dumps(
            {"nonce": "deadbeef00000000", "verdict": "pass", "reasons": []}
        )
        mock_client = MagicMock()
        mock_client.complete.return_value = mock_result

        with patch("secure_wiki.review.adversarial.get_review_client", return_value=mock_client):
            result = review_write(proposed=claims, source_text="source text")

        assert result.passed is False
        assert any("nonce mismatch" in r for r in result.reasons)

    def test_unparseable_response_blocks(self):
        """Reviewer returns garbage JSON → must fail closed."""
        claims = [_make_claim()]
        mock_result = MagicMock()
        mock_result.text = "this is not json at all !!!"
        mock_client = MagicMock()
        mock_client.complete.return_value = mock_result

        with patch("secure_wiki.review.adversarial.get_review_client", return_value=mock_client):
            result = review_write(proposed=claims, source_text="source text")

        assert result.passed is False
        assert result.reasons

    def test_valid_pass_verdict_accepted(self):
        """Reviewer returns correct nonce + pass verdict → result.passed is True."""
        claims = [_make_claim()]

        real_nonce_holder: list[str] = []

        def _fake_complete(system, user):
            # Extract the nonce from the user content so we can echo it back
            import re
            m = re.search(r"<proposed-([a-f0-9]+)>", user)
            nonce = m.group(1) if m else "bad"
            real_nonce_holder.append(nonce)
            result = MagicMock()
            result.text = json.dumps({"nonce": nonce, "verdict": "pass", "reasons": []})
            return result

        mock_client = MagicMock()
        mock_client.complete.side_effect = _fake_complete

        with patch("secure_wiki.review.adversarial.get_review_client", return_value=mock_client):
            result = review_write(proposed=claims, source_text="source text")

        assert result.passed is True
