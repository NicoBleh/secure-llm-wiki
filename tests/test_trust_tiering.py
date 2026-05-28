"""Tests for trust-tiering (Spec 4.3)."""
from __future__ import annotations

import pytest

from secure_wiki.models import TrustLevel
from secure_wiki.trust.tiering import TrustRegistry, assign_trust


class TestBuiltinRules:
    def test_mitre_attack_trusted(self):
        r = TrustRegistry()
        assert r.assign("https://attack.mitre.org/techniques/T1059") == TrustLevel.TRUSTED

    def test_mitre_atlas_trusted(self):
        r = TrustRegistry()
        assert r.assign("https://atlas.mitre.org/techniques/AML.T0051") == TrustLevel.TRUSTED

    def test_nvd_trusted(self):
        r = TrustRegistry()
        assert r.assign("https://nvd.nist.gov/vuln/detail/CVE-2024-1234") == TrustLevel.TRUSTED

    def test_owasp_trusted(self):
        r = TrustRegistry()
        assert r.assign("https://owasp.org/www-project-top-ten/") == TrustLevel.TRUSTED

    def test_arxiv_semi_trusted(self):
        r = TrustRegistry()
        assert r.assign("https://arxiv.org/abs/2401.00001") == TrustLevel.SEMI_TRUSTED

    def test_github_semi_trusted(self):
        r = TrustRegistry()
        assert r.assign("https://github.com/user/repo") == TrustLevel.SEMI_TRUSTED

    def test_stackoverflow_semi_trusted(self):
        r = TrustRegistry()
        assert r.assign("https://stackoverflow.com/questions/1234") == TrustLevel.SEMI_TRUSTED

    def test_unknown_domain_untrusted(self):
        r = TrustRegistry()
        assert r.assign("https://some-random-blog.example.com/post") == TrustLevel.UNTRUSTED

    def test_local_file_path_untrusted(self):
        r = TrustRegistry()
        assert r.assign("/local/path/to/document.pdf") == TrustLevel.UNTRUSTED


class TestUserRules:
    def test_user_rule_overrides_default(self):
        r = TrustRegistry()
        r.add_rule(pattern=r"example\.com", level=TrustLevel.TRUSTED, comment="internal")
        assert r.assign("https://example.com/doc") == TrustLevel.TRUSTED

    def test_user_rule_can_demote_to_untrusted(self):
        r = TrustRegistry()
        # Override github to untrusted for this registry instance
        r.add_rule(pattern=r"github\.com", level=TrustLevel.UNTRUSTED)
        assert r.assign("https://github.com/user/repo") == TrustLevel.UNTRUSTED

    def test_first_matching_rule_wins(self):
        r = TrustRegistry(extra_rules=[])
        r.add_rule(pattern=r"mitre\.org", level=TrustLevel.SEMI_TRUSTED)
        # User rule added last with add_rule() is prepended → takes precedence
        assert r.assign("https://attack.mitre.org/techniques/T1059") == TrustLevel.SEMI_TRUSTED


class TestPropagation:
    def test_weakest_propagates(self):
        levels = [TrustLevel.TRUSTED, TrustLevel.SEMI_TRUSTED, TrustLevel.UNTRUSTED]
        assert TrustLevel.weakest(levels) == TrustLevel.UNTRUSTED

    def test_weakest_all_trusted(self):
        assert TrustLevel.weakest([TrustLevel.TRUSTED, TrustLevel.TRUSTED]) == TrustLevel.TRUSTED

    def test_weakest_single(self):
        assert TrustLevel.weakest([TrustLevel.SEMI_TRUSTED]) == TrustLevel.SEMI_TRUSTED

    def test_weakest_empty_defaults_untrusted(self):
        assert TrustLevel.weakest([]) == TrustLevel.UNTRUSTED


class TestModuleLevelFunction:
    def test_assign_trust_known(self):
        assert assign_trust("https://attack.mitre.org/techniques/T1234") == TrustLevel.TRUSTED

    def test_assign_trust_unknown(self):
        assert assign_trust("https://unknown.example.net/article") == TrustLevel.UNTRUSTED
