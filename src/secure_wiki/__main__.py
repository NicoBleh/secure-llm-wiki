"""CLI entry point for secure-wiki.

Commands:
  ingest <source>   Run the full pipeline on a file or HTTP URI
  list              Show active wiki claims (--quarantine for quarantine)
  init              Initialize the wiki repo

Usage after install:
  secure-wiki ingest path/to/doc.txt
  secure-wiki ingest https://attack.mitre.org/...
  secure-wiki list
  secure-wiki list --quarantine
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from urllib.parse import urlparse

from .extraction.extractor import extract_claims
from .gate.write_gate import GateDecision, run_write_gate
from .ingestion.sanitizer import sanitize
from .models import SourceRef, TrustLevel
from .store.wiki_store import WikiStore
from .trust.tiering import assign_trust

_LINE = "─" * 60


def _read_source(source: str) -> tuple[str, str]:
    """Return (text, uri) from a file path or HTTP URL."""
    if source.startswith(("http://", "https://")):
        import urllib.request
        with urllib.request.urlopen(source, timeout=30) as resp:
            text = resp.read().decode("utf-8", errors="replace")
        return text, source
    path = Path(source)
    return path.read_text(encoding="utf-8"), f"file://{path.resolve()}"


def _domain(uri: str) -> str:
    parsed = urlparse(uri)
    return parsed.netloc or uri[:40]


def _source_id(source: str) -> str:
    if source.startswith(("http://", "https://")):
        parsed = urlparse(source)
        slug = parsed.path.rstrip("/").rsplit("/", 1)[-1] or parsed.netloc
        return f"{parsed.netloc}/{slug}"
    return Path(source).stem


def _preview(text: str, max_len: int = 72) -> str:
    flat = text.replace("\n", " ").strip()
    return flat[:max_len] + "…" if len(flat) > max_len else flat


# ------------------------------------------------------------------
# Commands
# ------------------------------------------------------------------

def cmd_init(args: argparse.Namespace) -> None:
    store = WikiStore()
    if (store.root / ".git").exists():
        print(f"Wiki repo already initialized at {store.root.resolve()}")
    else:
        store.init()
        print(f"Wiki repo initialized at {store.root.resolve()}")


def cmd_ingest(args: argparse.Namespace) -> None:
    print(f"\nIngesting: {args.source}")
    print(_LINE)

    # 1. Read source
    try:
        source_text, uri = _read_source(args.source)
    except Exception as exc:
        print(f"[error]    could not read source: {exc}")
        sys.exit(1)

    # 2. Sanitize
    report = sanitize(source_text)
    if report.is_suspicious:
        print(f"[sanitize] SUSPICIOUS — {', '.join(report.flags)}")
    else:
        print("[sanitize] clean")

    # 3. Trust
    trust = TrustLevel(args.trust) if args.trust else assign_trust(uri)
    note = "(manual override)" if args.trust else f"({_domain(uri)})"
    print(f"[trust]    {trust.value}  {note}")

    # 4. Build source ref
    source_ref = SourceRef(
        id=args.source_id or _source_id(args.source),
        uri=uri,
        section=args.section,
        content_hash=SourceRef.compute_hash(source_text),
    )

    # 5. Extract claims
    print("[extract]  calling extraction model…")
    claims = extract_claims(source_text, source_ref, trust)
    if not claims:
        print("[extract]  no claims extracted — model returned empty or unparseable response")
        sys.exit(0)
    print(f"[extract]  {len(claims)} claim(s) extracted")
    print()

    # 6. Gate + store each claim
    store = WikiStore()
    existing = store.load_claims()
    committed = quarantined = escalated = 0
    width = len(f"[gate {len(claims)}/{len(claims)}]") + 2

    for i, claim in enumerate(claims, 1):
        label = f"[gate {i}/{len(claims)}]".ljust(width)
        outcome = run_write_gate(claim, report, existing)

        if outcome.decision == GateDecision.COMMIT:
            store.save_claim(claim)
            existing.append(claim)
            committed += 1
            print(f"{label} COMMIT      {_preview(claim.text)}")
        elif outcome.decision == GateDecision.QUARANTINE:
            store.save_quarantined(claim, outcome.detail)
            quarantined += 1
            print(f"{label} QUARANTINE  {outcome.detail}")
        else:
            store.save_quarantined(claim, outcome.detail)
            escalated += 1
            print(f"{label} ESCALATE    {outcome.detail}")

    print()
    print(_LINE)
    print(f"  committed:   {committed}")
    print(f"  quarantined: {quarantined}")
    if escalated:
        print(f"  escalated:   {escalated}  <- human review required")
    print()


def cmd_list(args: argparse.Namespace) -> None:
    store = WikiStore()
    if args.quarantine:
        claims = store.load_quarantined()
        header = f"Quarantined claims ({len(claims)})"
    else:
        claims = store.load_claims()
        header = f"Active claims ({len(claims)})"

    print(f"\n{header}")
    print(_LINE)
    if not claims:
        print("  (none)")
    else:
        trust_sym = {
            "trusted": "[T]",
            "semi-trusted": "[S]",
            "untrusted": "[U]",
        }
        for claim in claims:
            sym = trust_sym.get(claim.trust_level.value, "[?]")
            print(f"  {sym} {claim.claim_id[:8]}  {_preview(claim.text, 58)}")
            print(f"           {claim.source.uri}")
    print()


# ------------------------------------------------------------------
# Argument parser
# ------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="secure-wiki",
        description="Secure LLM-Wiki — hardened against indirect prompt injection.",
    )
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    # init
    sub.add_parser("init", help="Initialize the wiki data repository")

    # ingest
    ingest_p = sub.add_parser("ingest", help="Ingest a source through the full pipeline")
    ingest_p.add_argument("source", help="File path or HTTP URI to ingest")
    ingest_p.add_argument(
        "--trust",
        choices=["trusted", "semi-trusted", "untrusted"],
        help="Override auto-detected trust level",
    )
    ingest_p.add_argument("--source-id", help="Human-readable identifier for this source")
    ingest_p.add_argument("--section", default="full", help="Section label (default: full)")

    # list
    list_p = sub.add_parser("list", help="List wiki claims")
    list_p.add_argument("--quarantine", action="store_true", help="Show quarantined claims")

    args = parser.parse_args()

    if args.command == "init":
        cmd_init(args)
    elif args.command == "ingest":
        cmd_ingest(args)
    elif args.command == "list":
        cmd_list(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
