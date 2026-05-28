"""Regression suite against the injection corpus (Spec 8).

Loads the manifest and verifies that every attack is stopped at the EXPECTED
gate, and that the benign control case passes all the way through to COMMIT.

TestSanitizerLayer  — gate 1 only (no LLM needed)
TestFullPipeline    — all 5 gates; review_write is mocked so tests are
                      deterministic and run without a live Ollama/Anthropic
                      connection.
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from secure_wiki.gate.write_gate import GateDecision, run_write_gate
from secure_wiki.ingestion.sanitizer import sanitize
from secure_wiki.models import Claim, ClaimStatus, SourceRef, TrustLevel
from secure_wiki.review.adversarial import ReviewResult

CORPUS = Path(__file__).parent / "injection_corpus"
MANIFEST = json.loads((CORPUS / "manifest.json").read_text())
CASES = MANIFEST["cases"]


def _load(case) -> str:
    return (CORPUS / case["file"]).read_text(encoding="utf-8")


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
class TestSanitizerLayer:
    """Checks the sanitizing stage against every corpus case."""

    def test_sanitizing_matches_manifest(self, case):
        report = sanitize(_load(case))
        flag_types = {f.split(":")[0] for f in report.flags}

        if case["expected_stop_gate"] == "sanitizing":
            for expected in case["expected_flags"]:
                assert expected in flag_types, (
                    f"{case['id']}: expected flag '{expected}' missing "
                    f"(found: {flag_types})"
                )
        elif case["expected_stop_gate"] is None:
            assert not report.is_suspicious, (
                f"{case['id']} is a control case but was flagged: {report.flags}"
            )


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
class TestFullPipeline:
    """Full pipeline regression: every attack must be stopped at its declared gate.

    review_write is mocked — the adversarial review LLM is not called, keeping
    tests fast and deterministic. The mock blocks exactly the cases whose
    expected_stop_gate is 'adversarial_review'.
    """

    def test_pipeline_decision(self, case):
        source_text = _load(case)
        sanitize_report = sanitize(source_text)
        source_ref = SourceRef(
            id=case["id"],
            uri=f"test://{case['id']}",
            section="test-section",
            content_hash=SourceRef.compute_hash(source_text),
        )
        trust = (
            TrustLevel.SEMI_TRUSTED
            if case["category"] == "control"
            else TrustLevel.UNTRUSTED
        )
        claim = Claim(text="extracted claim text", source=source_ref, trust_level=trust)

        # Case 07: simulate existing high-trust content the untrusted claim would overwrite.
        existing_claims: list[Claim] = []
        if case["expected_stop_gate"] == "write_gate":
            existing_claims = [
                Claim(
                    text="established trusted claim",
                    source=SourceRef(
                        id="trusted-source",
                        uri="test://trusted",
                        section="test-section",
                        content_hash=SourceRef.compute_hash("trusted content"),
                    ),
                    trust_level=TrustLevel.TRUSTED,
                    status=ClaimStatus.ACTIVE,
                )
            ]

        # Mock review_write: block only cases expected to fail at adversarial_review.
        review_verdict = ReviewResult(
            passed=(case["expected_stop_gate"] != "adversarial_review"),
            reasons=(
                ["manipulation detected: rule-change attempt"]
                if case["expected_stop_gate"] == "adversarial_review"
                else []
            ),
        )

        with patch("secure_wiki.gate.write_gate.review_write", return_value=review_verdict):
            outcome = run_write_gate(claim, sanitize_report, existing_claims)

        if case["expected_stop_gate"] is None:
            assert outcome.decision == GateDecision.COMMIT, (
                f"{case['id']}: expected COMMIT, got {outcome.decision} — {outcome.detail}"
            )
        else:
            assert outcome.decision == GateDecision.QUARANTINE, (
                f"{case['id']}: expected QUARANTINE, got {outcome.decision} — {outcome.detail}"
            )
