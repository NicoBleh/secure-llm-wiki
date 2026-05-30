"""CLI entry point for secure-wiki.

Commands:
  ingest <source>   Run the full pipeline on a file or HTTP URI
  list              Show active wiki claims (--quarantine for quarantine)
  context           Print wiki content as a safe, nonce-delimited context block
  init              Initialize the wiki repo

Usage after install:
  secure-wiki ingest path/to/doc.txt
  secure-wiki ingest https://attack.mitre.org/...
  secure-wiki list
  secure-wiki list --quarantine
  secure-wiki context
  secure-wiki context --min-trust trusted
"""
from __future__ import annotations

import argparse
import contextlib
import itertools
import re
import sys
import threading
import time
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse

# Load .env from the working directory (or any parent) automatically so users
# don't need to `source .env` before running the CLI.
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from .extraction.extractor import extract_claims
from .llm_client import UsageInfo
from .gate.write_gate import GateDecision, run_write_gate
from .ingestion.sanitizer import sanitize
from .llm_client import get_embed_client, get_review_client
from .models import SourceRef, TrustLevel
from .prompts import QUERY_TASK_PROMPT
from .read.hygiene import load_for_context
from .store.embedding_store import EmbeddingStore
from .store.wiki_store import WikiStore
from .trust.tiering import assign_trust, load_similarity_config

_LINE = "─" * 60
_MAX_CHARS = 8_000  # extraction model context limit — keep input focused
_SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]


@contextlib.contextmanager
def _spinner(message: str):
    """Animate a spinner beside *message* while the body executes.

    Skips animation when stdout is not a TTY (piped output stays clean).
    """
    if not sys.stdout.isatty():
        sys.stdout.write(f"{message}\n")
        sys.stdout.flush()
        yield
        return

    stop = threading.Event()

    def _spin() -> None:
        for frame in itertools.cycle(_SPINNER_FRAMES):
            if stop.is_set():
                break
            sys.stdout.write(f"\r{frame} {message}")
            sys.stdout.flush()
            time.sleep(0.08)

    t = threading.Thread(target=_spin, daemon=True)
    t.start()
    try:
        yield
    finally:
        stop.set()
        t.join()
        sys.stdout.write(f"\r  {message}\n")
        sys.stdout.flush()


class _HtmlStripper(HTMLParser):
    """Extract visible text from HTML, skipping scripts, styles, and nav."""
    _SKIP = {"script", "style", "head", "nav", "footer", "header", "noscript"}
    _BLOCK = {"p", "div", "section", "article", "h1", "h2", "h3", "h4", "li", "tr", "br"}

    def __init__(self) -> None:
        super().__init__()
        self._skip_depth = 0
        self._parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list) -> None:
        if tag in self._SKIP:
            self._skip_depth += 1
        elif tag in self._BLOCK:
            self._parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in self._SKIP:
            self._skip_depth = max(0, self._skip_depth - 1)

    def handle_data(self, data: str) -> None:
        if self._skip_depth == 0:
            self._parts.append(data)

    def get_text(self) -> str:
        text = "".join(self._parts)
        return re.sub(r"\n{3,}", "\n\n", text).strip()


def _strip_html(content: str) -> str:
    stripper = _HtmlStripper()
    stripper.feed(content)
    return stripper.get_text()


def _read_source(source: str) -> tuple[str, str]:
    """Return (text, uri) from a file path or HTTP URL.

    HTML content is stripped to plain text before returning. Content is
    truncated to _MAX_CHARS so the extraction model receives a focused input.
    """
    if source.startswith(("http://", "https://")):
        import urllib.request
        with urllib.request.urlopen(source, timeout=30) as resp:
            content_type = resp.headers.get("Content-Type", "")
            raw = resp.read().decode("utf-8", errors="replace")
        if "html" in content_type or raw.lstrip().startswith(("<!DOCTYPE", "<html")):
            raw = _strip_html(raw)
        return raw[:_MAX_CHARS], source
    path = Path(source)
    text = path.read_text(encoding="utf-8")
    return text[:_MAX_CHARS], f"file://{path.resolve()}"


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
    with _spinner("[extract]  calling extraction model…"):
        claims, extract_usage = extract_claims(source_text, source_ref, trust)
    if not claims:
        print("[extract]  no claims extracted — model returned empty or unparseable response")
        sys.exit(0)
    print(f"[extract]  {len(claims)} claim(s) extracted")
    print()

    # 6. Gate + store each claim
    store = WikiStore()
    emb_store = EmbeddingStore(store)
    existing = store.load_claims()
    existing_embeddings = emb_store.load_all()
    sim_cfg = load_similarity_config()

    # Pre-compute embeddings for all new claims in one pass; fall back gracefully
    try:
        embed_client = get_embed_client()
        new_embeddings = {c.claim_id: embed_client.embed(c.text) for c in claims}
        print(f"[embed]    embeddings computed for {len(claims)} claim(s)")
    except Exception as exc:
        print(f"[embed]    unavailable ({exc}), Gate 5 falls back to section heuristic")
        new_embeddings = {}

    committed = quarantined = escalated = 0
    width = len(f"[gate {len(claims)}/{len(claims)}]") + 2

    for i, claim in enumerate(claims, 1):
        label = f"[gate {i}/{len(claims)}]".ljust(width)
        outcome = run_write_gate(
            claim,
            report,
            existing,
            new_embedding=new_embeddings.get(claim.claim_id),
            existing_embeddings=existing_embeddings or None,
            duplicate_threshold=sim_cfg["duplicate_threshold"],
            conflict_threshold=sim_cfg["conflict_threshold"],
        )

        if outcome.decision == GateDecision.COMMIT:
            store.save_claim(claim)
            existing.append(claim)
            if claim.claim_id in new_embeddings:
                emb_store.save(claim.claim_id, new_embeddings[claim.claim_id])
                existing_embeddings[claim.claim_id] = new_embeddings[claim.claim_id]
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
    print(f"  tokens:      {extract_usage.input_tokens} in / {extract_usage.output_tokens} out")
    print()


def cmd_query(args: argparse.Namespace) -> None:
    min_trust = TrustLevel(args.min_trust)
    ctx = load_for_context(min_trust=min_trust, include_pending=args.include_pending)

    if ctx.claim_count == 0:
        print(f"\n[query] Wiki is empty (min_trust={args.min_trust}). Run 'secure-wiki ingest' first.")
        sys.exit(1)

    system = f"{ctx.system_note}\n\n{ctx.context_block}\n\n{QUERY_TASK_PROMPT}"
    client = get_review_client()

    print(f"\n[query] {ctx.claim_count} claim(s) loaded (min_trust={args.min_trust})")
    print("[query] Type 'exit' to quit.")
    print(_LINE)

    while True:
        try:
            question = input("\n> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if question.lower() in {"exit", "quit", "q"}:
            break
        if not question:
            continue
        with _spinner("thinking…"):
            result = client.complete(system, question)
        print()
        print(result.text)
        u = result.usage
        print(f"\n[tokens] {u.input_tokens} in / {u.output_tokens} out  (total {u.total_tokens})")


def cmd_context(args: argparse.Namespace) -> None:
    min_trust = TrustLevel(args.min_trust)
    ctx = load_for_context(min_trust=min_trust, include_pending=args.include_pending)
    print(f"\n# System note ({ctx.claim_count} claim(s), min_trust={args.min_trust})")
    print(_LINE)
    print(ctx.system_note)
    print()
    print("# Context block")
    print(_LINE)
    print(ctx.context_block)
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

    # query
    query_p = sub.add_parser("query", help="Open an interactive wiki Q&A session")
    query_p.add_argument(
        "--min-trust",
        choices=["trusted", "semi-trusted", "untrusted"],
        default="semi-trusted",
        help="Minimum trust level to include (default: semi-trusted)",
    )
    query_p.add_argument(
        "--include-pending",
        action="store_true",
        help="Also include PENDING (unreviewed) claims",
    )

    # context
    ctx_p = sub.add_parser("context", help="Print wiki content as a safe context block")
    ctx_p.add_argument(
        "--min-trust",
        choices=["trusted", "semi-trusted", "untrusted"],
        default="semi-trusted",
        help="Minimum trust level to include (default: semi-trusted)",
    )
    ctx_p.add_argument(
        "--include-pending",
        action="store_true",
        help="Also include PENDING (unreviewed) claims",
    )

    # list
    list_p = sub.add_parser("list", help="List wiki claims")
    list_p.add_argument("--quarantine", action="store_true", help="Show quarantined claims")

    args = parser.parse_args()

    if args.command == "init":
        cmd_init(args)
    elif args.command == "ingest":
        cmd_ingest(args)
    elif args.command == "query":
        cmd_query(args)
    elif args.command == "context":
        cmd_context(args)
    elif args.command == "list":
        cmd_list(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
