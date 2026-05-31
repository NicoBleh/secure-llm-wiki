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
from concurrent.futures import ThreadPoolExecutor, as_completed
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
from .review.adversarial import review_write
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
_SUPPORTED_EXTENSIONS = {".txt", ".md", ".html", ".htm", ".rst", ".csv", ".pdf"}
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


def _read_pdf(path: Path) -> str:
    """Extract plain text from a PDF file using pypdf."""
    import logging
    try:
        from pypdf import PdfReader
    except ImportError:
        raise ImportError("PDF support requires pypdf: pip install pypdf")
    logging.getLogger("pypdf").setLevel(logging.ERROR)
    reader = PdfReader(path)
    pages = [page.extract_text() or "" for page in reader.pages]
    return "\n\n".join(p.strip() for p in pages if p.strip())


def _read_source(source: str) -> tuple[str, str]:
    """Return (text, uri) from a file path or HTTP URL.

    HTML content is stripped to plain text; PDFs are extracted via pypdf.
    Content is truncated to _MAX_CHARS so the extraction model stays focused.
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
    if path.suffix.lower() == ".pdf":
        text = _read_pdf(path)
    else:
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


def _prompt_trust(detected: "TrustLevel", domain: str) -> "TrustLevel":
    """Show the auto-detected trust level and let the user confirm or override it.

    Skips the prompt when stdin is not a TTY (e.g. piped/scripted ingestion).
    """
    _SHORT = {"t": TrustLevel.TRUSTED, "s": TrustLevel.SEMI_TRUSTED, "u": TrustLevel.UNTRUSTED}
    _LABELS = {
        TrustLevel.TRUSTED: "trusted",
        TrustLevel.SEMI_TRUSTED: "semi-trusted",
        TrustLevel.UNTRUSTED: "untrusted",
    }

    print(f"[trust]    {detected.value}  ({domain})")

    if not sys.stdin.isatty():
        return detected

    print("           How trustworthy is this source?")
    print("           [t] trusted   [s] semi-trusted   [u] untrusted   [Enter] keep")
    try:
        raw = input("           > ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return detected

    chosen = _SHORT.get(raw, detected)
    if chosen != detected:
        print(f"[trust]    overridden → {_LABELS[chosen]}")
    return chosen


def _prompt_min_trust(default: "TrustLevel") -> "TrustLevel":
    """Ask which minimum trust level to load for a query session.

    Skips the prompt when stdin is not a TTY.
    """
    _SHORT = {"t": TrustLevel.TRUSTED, "s": TrustLevel.SEMI_TRUSTED, "u": TrustLevel.UNTRUSTED}
    _LABELS = {
        TrustLevel.TRUSTED: "trusted",
        TrustLevel.SEMI_TRUSTED: "semi-trusted",
        TrustLevel.UNTRUSTED: "untrusted",
    }

    if not sys.stdin.isatty():
        return default

    print(f"\n[query] Minimum trust level to include?")
    print(f"        [t] trusted   [s] semi-trusted   [u] untrusted   [Enter] {default.value}")
    try:
        raw = input("        > ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return default

    chosen = _SHORT.get(raw, default)
    if chosen != default:
        print(f"[query] overridden → {_LABELS[chosen]}")
    return chosen


def _collect_files(folder: Path, recursive: bool = False) -> list[Path]:
    """Return sorted list of files with supported extensions in folder."""
    pattern = "**/*" if recursive else "*"
    return sorted(
        f for f in folder.glob(pattern)
        if f.is_file() and f.suffix.lower() in _SUPPORTED_EXTENSIONS
    )


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


def _run_pipeline(
    source: str,
    trust: TrustLevel,
    source_id_override: str | None,
    section: str,
    store: WikiStore,
    emb_store: EmbeddingStore,
    existing: list,
    existing_embeddings: dict,
    sim_cfg: dict,
) -> tuple[int, int, int, UsageInfo]:
    """Run steps 1–6 of the ingest pipeline for a single source.

    Mutates *existing* and *existing_embeddings* in place so subsequent files
    in a folder run benefit from duplicate/conflict detection against all
    already-processed claims.

    Returns (committed, quarantined, escalated, usage).
    """
    # 1. Read source
    try:
        source_text, uri = _read_source(source)
    except Exception as exc:
        print(f"[error]    could not read source: {exc}")
        return 0, 0, 0, UsageInfo()

    # 2. Sanitize
    report = sanitize(source_text)
    if report.is_suspicious:
        print(f"[sanitize] SUSPICIOUS — {', '.join(report.flags)}")
    else:
        print("[sanitize] clean")

    # 3. Build source ref
    source_ref = SourceRef(
        id=source_id_override or _source_id(source),
        uri=uri,
        section=section,
        content_hash=SourceRef.compute_hash(source_text),
    )

    # 4. Extract claims
    with _spinner("[extract]  calling extraction model…"):
        claims, extract_usage, parse_error = extract_claims(source_text, source_ref, trust)
    if not claims:
        if parse_error:
            print(f"[extract]  no claims extracted — {parse_error}")
        else:
            print("[extract]  no claims extracted — model returned an empty list")
        return 0, 0, 0, extract_usage
    print(f"[extract]  {len(claims)} claim(s) extracted")
    print()

    # 5. Embeddings — computed in parallel
    new_embeddings: dict[str, list[float]] = {}
    try:
        embed_client = get_embed_client()
        with _spinner(f"[embed]    computing embeddings for {len(claims)} claim(s)…"):
            with ThreadPoolExecutor() as pool:
                futures = {pool.submit(embed_client.embed, c.text): c.claim_id for c in claims}
                for fut in as_completed(futures):
                    cid = futures[fut]
                    try:
                        new_embeddings[cid] = fut.result()
                    except Exception:
                        pass
        print(f"[embed]    {len(new_embeddings)}/{len(claims)} embedding(s) computed")
    except Exception as exc:
        print(f"[embed]    unavailable ({exc}), Gate 5 falls back to section heuristic")

    # 6. Batch adversarial review — one call for all claims from this source
    existing_trusted = [
        c for c in existing
        if c.trust_level.value == "trusted" and c.status.value == "active"
    ]
    with _spinner("[review]   adversarial review (batch)…"):
        batch_review = review_write(
            proposed=claims,
            source_text=source_text,
            existing_high_trust=existing_trusted or None,
        )
    status = "PASS" if batch_review.passed else "BLOCK"
    print(f"[review]   {status}  {'; '.join(batch_review.reasons) if batch_review.reasons else 'no issues'}")
    print()

    # 7. Gate + store (review result pre-supplied — no extra LLM call per claim)
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
            review_result=batch_review,
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

    return committed, quarantined, escalated, extract_usage


def cmd_ingest(args: argparse.Namespace) -> None:
    # Resolve sources — single file/URL or an entire folder
    is_url = args.source.startswith(("http://", "https://"))
    source_path = Path(args.source) if not is_url else None

    if source_path and source_path.is_dir():
        files = _collect_files(source_path, recursive=getattr(args, "recursive", False))
        if not files:
            print(f"\n[error]    no supported files found in {source_path}")
            print(f"           supported extensions: {', '.join(sorted(_SUPPORTED_EXTENSIONS))}")
            sys.exit(1)
        sources = [str(f) for f in files]
        print(f"\nIngesting folder: {source_path.resolve()}  ({len(sources)} file(s))")
        print(_LINE)
        if args.trust:
            trust = TrustLevel(args.trust)
            print(f"[trust]    {trust.value}  (manual override)")
        else:
            trust = assign_trust(str(source_path))
            trust = _prompt_trust(trust, str(source_path.name))
    else:
        sources = [args.source]
        trust = None  # resolved per-source below

    # Shared wiki state — kept across files so cross-file duplicate detection works
    store = WikiStore()
    emb_store = EmbeddingStore(store)
    existing = store.load_claims()
    existing_embeddings = emb_store.load_all()
    sim_cfg = load_similarity_config()

    is_folder = len(sources) > 1
    total_committed = total_quarantined = total_escalated = 0
    total_usage = UsageInfo()

    for idx, source in enumerate(sources, 1):
        if is_folder:
            print(f"\n  [{idx}/{len(sources)}] {Path(source).name}")
        else:
            print(f"\nIngesting: {source}")
        print(_LINE)

        # Trust — already set for folders; resolve per-source for single ingests
        if trust is None:
            uri_hint = source if is_url else f"file://{Path(source).resolve()}"
            if args.trust:
                file_trust = TrustLevel(args.trust)
                print(f"[trust]    {file_trust.value}  (manual override)")
            else:
                file_trust = assign_trust(uri_hint)
                file_trust = _prompt_trust(file_trust, _domain(uri_hint))
        else:
            file_trust = trust

        c, q, e, usage = _run_pipeline(
            source, file_trust,
            args.source_id if not is_folder else None,
            args.section,
            store, emb_store, existing, existing_embeddings, sim_cfg,
        )
        total_committed += c
        total_quarantined += q
        total_escalated += e
        total_usage = total_usage + usage

        if not is_folder:
            if c + q + e == 0:
                sys.exit(0)
            print()
            print(_LINE)
            print(f"  committed:   {c}")
            print(f"  quarantined: {q}")
            if e:
                print(f"  escalated:   {e}  <- human review required")
            print(f"  tokens:      {usage.input_tokens} in / {usage.output_tokens} out")
            print()

    if is_folder:
        print()
        print(_LINE)
        print(f"  files:       {len(sources)}")
        print(f"  committed:   {total_committed}")
        print(f"  quarantined: {total_quarantined}")
        if total_escalated:
            print(f"  escalated:   {total_escalated}  <- human review required")
        print(f"  tokens:      {total_usage.input_tokens} in / {total_usage.output_tokens} out")
        print()


def cmd_query(args: argparse.Namespace) -> None:
    min_trust = _prompt_min_trust(TrustLevel(args.min_trust))
    ctx = load_for_context(min_trust=min_trust, include_pending=args.include_pending)

    if ctx.claim_count == 0:
        print(f"\n[query] Wiki is empty (min_trust={min_trust.value}). Run 'secure-wiki ingest' first.")
        sys.exit(1)

    system = f"{ctx.system_note}\n\n{ctx.context_block}\n\n{QUERY_TASK_PROMPT}"
    client = get_review_client()

    print(f"\n[query] {ctx.claim_count} claim(s) loaded (min_trust={min_trust.value})")
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
        stream = client.stream(system, question)
        with _spinner("thinking…"):
            first = next(stream)  # blocks until first token — spinner drops here
        print()
        u = UsageInfo()
        for chunk in itertools.chain([first], stream):
            if isinstance(chunk, UsageInfo):
                u = chunk
            else:
                print(chunk, end="", flush=True)
        print(f"\n\n[tokens] {u.input_tokens} in / {u.output_tokens} out  (total {u.total_tokens})")


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


def _confirm(prompt: str) -> bool:
    """Ask for y/N confirmation. Returns True only on explicit 'y'."""
    try:
        return input(f"{prompt} [y/N] ").strip().lower() == "y"
    except (EOFError, KeyboardInterrupt):
        print()
        return False


def cmd_clear(args: argparse.Namespace) -> None:
    store = WikiStore()
    emb_store = EmbeddingStore(store)

    if args.quarantine:
        count = len(store.load_quarantined())
        if count == 0:
            print("\n[clear] Quarantine is already empty.")
            return
        print(f"\n[clear] This will permanently delete {count} quarantined claim(s).")
        if not _confirm("[clear] Proceed?"):
            print("[clear] Aborted.")
            return
        deleted = store.delete_quarantine()
        for cid in deleted:
            emb_store.delete(cid)
        print(f"[clear] Removed {len(deleted)} quarantined claim(s).")

    elif args.trust:
        all_claims = store.load_claims(status=None) + store.load_quarantined()
        matching = [c for c in all_claims if c.trust_level.value == args.trust]
        if not matching:
            print(f"\n[clear] No claims with trust level '{args.trust}' found.")
            return
        print(f"\n[clear] This will permanently delete {len(matching)} '{args.trust}' claim(s)"
              f" from pages and quarantine.")
        if not _confirm("[clear] Proceed?"):
            print("[clear] Aborted.")
            return
        deleted = store.delete_by_trust(args.trust)
        for cid in deleted:
            emb_store.delete(cid)
        print(f"[clear] Removed {len(deleted)} claim(s).")

    elif args.reset:
        total = len(store.load_claims(status=None)) + len(store.load_quarantined())
        keep = getattr(args, "keep_history", False)
        if total == 0:
            print("\n[clear] Wiki is already empty.")
            return
        print(f"\n[clear] FULL RESET — permanently deletes ALL {total} claim(s) (pages + quarantine).")
        if keep:
            print("[clear] Git history will be preserved (--keep-history).")
        else:
            print("[clear] Git repo will be wiped and re-initialized — history gone.")
        print("[clear] trust_rules.yaml is always preserved.")
        if not _confirm("[clear] Proceed?"):
            print("[clear] Aborted.")
            return
        removed = store.reset(keep_history=keep)
        emb_store.delete_all()
        print(f"[clear] Wiki reset — {removed} claim(s) removed.")

    else:
        print("\n[clear] Specify one of: --quarantine, --trust <level>, --reset")
        sys.exit(1)


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
    ingest_p.add_argument(
        "--recursive", action="store_true",
        help="When source is a folder, also scan sub-folders",
    )

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

    # clear
    clear_p = sub.add_parser("clear", help="Delete claims from the wiki")
    clear_grp = clear_p.add_mutually_exclusive_group(required=True)
    clear_grp.add_argument(
        "--quarantine", action="store_true",
        help="Delete all quarantined claims",
    )
    clear_grp.add_argument(
        "--trust",
        choices=["trusted", "semi-trusted", "untrusted"],
        metavar="LEVEL",
        help="Delete all claims at this trust level (pages + quarantine)",
    )
    clear_grp.add_argument(
        "--reset", action="store_true",
        help="Full reset — wipes git repo and all claims (trust_rules.yaml preserved)",
    )
    clear_p.add_argument(
        "--keep-history", action="store_true",
        help="With --reset: commit removal instead of wiping the git repo",
    )

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
    elif args.command == "clear":
        cmd_clear(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
