"""Trust-tiering: assigns a TrustLevel to a source URI (Spec 4.3).

Rules are matched top-to-bottom; the first match wins. Sources with no matching
rule default to UNTRUSTED. User-defined rules in wiki_data/trust_rules.yaml are
prepended and therefore take precedence over the built-in defaults.

Propagation (Spec 4.3): a claim inherits the WEAKEST trust level of all its
sources. TrustLevel.weakest() in models.py handles multi-source propagation;
assign_trust() handles per-source assignment.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from ..models import TrustLevel

# Resolved at import time: src/secure_wiki/trust/ → src/secure_wiki/ → src/ → project root
_DEFAULT_RULES_FILE = Path(__file__).parent.parent.parent.parent / "wiki_data" / "trust_rules.yaml"

_BUILTIN_RULES: list[dict] = [
    {"pattern": r"attack\.mitre\.org",   "level": "trusted",      "comment": "MITRE ATT&CK"},
    {"pattern": r"atlas\.mitre\.org",    "level": "trusted",      "comment": "MITRE ATLAS"},
    {"pattern": r"nvd\.nist\.gov",       "level": "trusted",      "comment": "NIST NVD"},
    {"pattern": r"cve\.mitre\.org",      "level": "trusted",      "comment": "MITRE CVE"},
    {"pattern": r"owasp\.org",           "level": "trusted",      "comment": "OWASP"},
    {"pattern": r"arxiv\.org",           "level": "semi-trusted", "comment": "arXiv preprints"},
    {"pattern": r"github\.com",          "level": "semi-trusted", "comment": "GitHub"},
    {"pattern": r"stackoverflow\.com",   "level": "semi-trusted", "comment": "Stack Overflow"},
]


@dataclass
class TrustRule:
    """A single URI-pattern → TrustLevel mapping."""
    pattern: str
    level: TrustLevel
    comment: str = ""

    def matches(self, uri: str) -> bool:
        return bool(re.search(self.pattern, uri, re.I))


class TrustRegistry:
    """Ordered list of TrustRules; first match wins, default is UNTRUSTED.

    Load order: user rules (from YAML) → built-in rules.
    User rules are prepended so they can override or tighten built-in defaults.
    """

    def __init__(self, extra_rules: list[TrustRule] | None = None) -> None:
        builtin = [
            TrustRule(
                pattern=r["pattern"],
                level=TrustLevel(r["level"]),
                comment=r.get("comment", ""),
            )
            for r in _BUILTIN_RULES
        ]
        self._rules: list[TrustRule] = (extra_rules or []) + builtin

    @classmethod
    def from_yaml(cls, path: Path | None = None) -> TrustRegistry:
        """Load user rules from a YAML file, falling back to built-ins only."""
        rules_path = path or _DEFAULT_RULES_FILE
        extra: list[TrustRule] = []
        if rules_path.exists():
            raw = yaml.safe_load(rules_path.read_text()) or {}
            for entry in raw.get("rules", []):
                extra.append(
                    TrustRule(
                        pattern=entry["pattern"],
                        level=TrustLevel(entry["level"]),
                        comment=entry.get("comment", ""),
                    )
                )
        return cls(extra_rules=extra)

    def assign(self, uri: str) -> TrustLevel:
        """Return the TrustLevel for uri; UNTRUSTED if no rule matches."""
        for rule in self._rules:
            if rule.matches(uri):
                return rule.level
        return TrustLevel.UNTRUSTED

    def add_rule(self, pattern: str, level: TrustLevel, comment: str = "") -> None:
        """Prepend a rule so it takes precedence over all existing rules."""
        self._rules.insert(0, TrustRule(pattern=pattern, level=level, comment=comment))


_registry: TrustRegistry | None = None


def _get_registry() -> TrustRegistry:
    global _registry
    if _registry is None:
        _registry = TrustRegistry.from_yaml()
    return _registry


def assign_trust(uri: str) -> TrustLevel:
    """Assign a TrustLevel to a source URI using the default registry."""
    return _get_registry().assign(uri)
