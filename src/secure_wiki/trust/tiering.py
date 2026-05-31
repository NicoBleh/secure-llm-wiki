"""Trust-tiering: assigns a TrustLevel to a source URI (Spec 4.3).

Rules are matched top-to-bottom; the first match wins. Sources with no matching
rule default to UNTRUSTED. User-defined rules in wiki_data/trust_rules.yaml are
prepended and therefore take precedence over the built-in defaults.

Propagation (Spec 4.3): a claim inherits the WEAKEST trust level of all its
sources. TrustLevel.weakest() in models.py handles multi-source propagation;
assign_trust() handles per-source assignment.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import yaml

from ..models import TrustLevel


def _rules_file() -> Path:
    """Resolve trust_rules.yaml from $WIKI_DATA_PATH or the default location."""
    wiki_root = os.environ.get(
        "WIKI_DATA_PATH",
        str(Path(__file__).parent.parent.parent.parent / "wiki_data"),
    )
    return Path(wiki_root) / "trust_rules.yaml"


def _host(uri: str) -> str:
    """Return the lower-cased hostname of uri, or '' for local paths."""
    return (urlparse(uri).hostname or "").lower()


# Patterns are plain domain names (suffix-match, not free regex).
# A rule matches when the URI's hostname equals the domain exactly,
# or ends with '.<domain>' (legitimate subdomain).
# This prevents trust-elevation via:
#   https://evil.com/path?ref=attack.mitre.org     (query-string bypass)
#   https://attack.mitre.org.attacker.net/x        (hostname suffix abuse)
_BUILTIN_RULES: list[dict] = [
    {"pattern": "attack.mitre.org",   "level": "trusted",      "comment": "MITRE ATT&CK"},
    {"pattern": "atlas.mitre.org",    "level": "trusted",      "comment": "MITRE ATLAS"},
    {"pattern": "nvd.nist.gov",       "level": "trusted",      "comment": "NIST NVD"},
    {"pattern": "cve.mitre.org",      "level": "trusted",      "comment": "MITRE CVE"},
    {"pattern": "owasp.org",          "level": "trusted",      "comment": "OWASP"},
    {"pattern": "arxiv.org",          "level": "semi-trusted", "comment": "arXiv preprints"},
    {"pattern": "github.com",         "level": "semi-trusted", "comment": "GitHub"},
    {"pattern": "stackoverflow.com",  "level": "semi-trusted", "comment": "Stack Overflow"},
]


@dataclass
class TrustRule:
    """A single domain → TrustLevel mapping.

    pattern is a plain domain name (e.g. 'attack.mitre.org').
    Matching is host-only, suffix-anchored: the URI hostname must equal the
    domain exactly or end with '.<domain>'.  Free regex is not supported —
    this prevents attackers from constructing URIs that happen to contain a
    trusted domain in a query string or path component.
    """
    pattern: str
    level: TrustLevel
    comment: str = ""

    def matches(self, uri: str) -> bool:
        host = _host(uri)
        # Strip any leftover regex escapes from YAML rules that predate this format
        domain = self.pattern.replace(r"\.", ".").lstrip("^").rstrip("$").lower()
        return host == domain or host.endswith("." + domain)


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
        rules_path = path or _rules_file()
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


def load_similarity_config(path: Path | None = None) -> dict[str, float]:
    """Load Gate 5 similarity thresholds from trust_rules.yaml.

    Returns a dict with keys 'duplicate_threshold' and 'conflict_threshold'.
    Falls back to safe defaults if the file or section is missing.
    """
    from ..gate.write_gate import DEFAULT_CONFLICT_THRESHOLD, DEFAULT_DUPLICATE_THRESHOLD

    defaults = {
        "duplicate_threshold": DEFAULT_DUPLICATE_THRESHOLD,
        "conflict_threshold": DEFAULT_CONFLICT_THRESHOLD,
    }
    rules_path = path or _rules_file()
    if not rules_path.exists():
        return defaults
    raw = yaml.safe_load(rules_path.read_text()) or {}
    cfg = raw.get("similarity", {})
    return {
        "duplicate_threshold": float(cfg.get("duplicate_threshold", defaults["duplicate_threshold"])),
        "conflict_threshold": float(cfg.get("conflict_threshold", defaults["conflict_threshold"])),
    }
