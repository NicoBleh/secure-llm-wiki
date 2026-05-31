# Roadmap

Planned enhancements beyond the current implementation. Grouped by theme.

---

## Recently completed

The following items were in the original roadmap and have since been implemented:

- **Semantic consistency check (Gate 5)** — embedding-based cosine similarity with configurable thresholds in `trust_rules.yaml` ✅
- **`secure-wiki query`** — interactive Q&A session against the wiki, with streaming output ✅
- **Folder ingestion** — `secure-wiki ingest /path/` ingests all supported files; `--recursive` for sub-folders ✅
- **PDF support** — `.pdf` files extracted via `pypdf` ✅
- **Interactive trust prompts** — trust level confirmed at ingestion and query startup ✅
- **Token usage tracking** — input/output tokens reported after every LLM call ✅
- **Batch adversarial review** — one review call per source instead of per claim ✅
- **Parallel embeddings** — concurrent embed calls via `ThreadPoolExecutor` ✅
- **Streaming query responses** — live token output with spinner until first token arrives ✅
- **`secure-wiki clear`** — `--quarantine`, `--trust <level>`, `--reset` (wipes git history by default) ✅
- **Review retry logic** — retries on unparseable model responses before blocking ✅

---

## Security depth

### Promote from quarantine
**Current state:** Quarantined claims can be listed but not promoted without manual file editing.

**Goal:** `secure-wiki promote <claim-id> [--trust <level>]` moves a quarantined claim to active, optionally re-tiering its trust level, and commits the change.

**Why it matters:** The current human-in-the-loop path requires direct file system access. A proper promote command completes the quarantine workflow.

---

### User feedback loop on query answers
**Current state:** Query answers are shown but user reactions are not captured.

**Goal:** After each query answer, optionally ask the user to rate it. A negative rating retroactively flags the claims that contributed as pending review, tightening the trust signal over time.

**Why it matters:** Turns passive query use into active quality signal — the wiki improves through use.

---

### Trust decay
**Current state:** A `trusted` claim stays trusted indefinitely once committed.

**Goal:** Claims age out of `trusted` toward `semi-trusted` after a configurable period (e.g. 90 days) unless explicitly re-confirmed. Configurable in `trust_rules.yaml`.

**Why it matters:** Fact-moving domains (security advisories, library documentation) need periodic re-validation. Static trust accumulates stale knowledge.

---

### Audit log
**Current state:** Gate decisions and sanitizer flags are printed to stdout and not persisted.

**Goal:** Write every pipeline event to a structured append-only log at `audit/YYYY-MM-DD.jsonl` in the wiki repo. Add `secure-wiki audit [--since DATE]` to query it.

**Why it matters:** The forensic audit trail currently lives only in git commit messages. A structured log makes pipeline events queryable and machine-readable.

---

### Unicode homoglyph detection
**Current state:** The sanitizer catches zero-width chars, bidi overrides, and invisible codepoints but not look-alike substitutions (е vs e, а vs a, etc.).

**Goal:** Add a homoglyph detection pass using Unicode confusables data. Flag strings where the skeleton-normalized form matches an instruction pattern even if the raw string does not.

---

## Usability

### `--dry-run` flag on ingest
**Goal:** Show what would be committed/quarantined without writing anything or creating git commits. Useful for previewing before ingesting a large or unknown source.

---

### URL shallow crawl
**Current state:** `secure-wiki ingest <url>` fetches a single page.

**Goal:** Add `--depth N` to follow links up to N hops from the seed URL, ingesting each page as a separate source with its own provenance and trust level.

---

## Portfolio / red-teaming

### Extended injection corpus
**Goal:** Add attack vectors not currently covered:

| ID | Attack | Expected gate |
|----|--------|---------------|
| 09 | Unicode homoglyph substitution in instruction pattern | sanitizing |
| 10 | Multi-ingestion attack (benign first pass, payload second) | write_gate / consistency |
| 11 | Adversarial frontmatter injection (payload in YAML keys) | sanitizing |
| 12 | Encoding chain (URL-encoded inside base64) | sanitizing |
| 13 | Claim supersession abuse (fake supersedes pointer) | write_gate / provenance |

---

### Benchmark mode
**Goal:** `secure-wiki benchmark` runs the full injection corpus against a live model pair and reports which gates fired, timing per stage, and whether any attacks slipped through. Useful for comparing model pairs (e.g. `llama3.1:8b + mistral` vs `qwen2.5 + phi4`).
