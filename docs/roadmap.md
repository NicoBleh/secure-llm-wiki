# Roadmap

Planned enhancements beyond the initial spec. Grouped by theme.

---

## Security depth

### Semantic consistency check (Gate 5)
**Current state:** Gate 5 uses a section-match heuristic — a new claim conflicts with
an existing one only if they share the same `source.section` and come from different
sources. This misses cross-topic contradictions and produces false positives on
legitimate parallel sources.

**Goal:** Replace with embedding-based similarity. Compute cosine distance between
the new claim's text and all existing high-trust claims. Flag pairs above a threshold
as potential conflicts → ESCALATE.

**Implementation sketch:**
- Use `nomic-embed-text` (already installed in Ollama) via the Ollama embed API
- Store embeddings alongside `.meta.json` in the wiki repo
- On each write, compare new claim embedding against existing ones
- Threshold configurable in `trust_rules.yaml`

**Why it matters:** The current heuristic can be trivially bypassed by using a
different section label. Embedding-based detection is robust to rephrasing.

---

### Audit log
**Current state:** Sanitizer flags and gate decisions are printed to stdout and lost.

**Goal:** Write every pipeline event (sanitizer flags, gate outcomes, review verdicts)
to a structured append-only log in the wiki repo at `audit/YYYY-MM-DD.jsonl`.

**Implementation sketch:**
- `AuditEvent` dataclass: timestamp, event_type, claim_id, source_uri, detail
- Each gate outcome and sanitizer flag writes one event
- `secure-wiki audit [--since DATE]` command to query the log
- Log is git-committed with the claim it describes

**Why it matters:** The spec requires forensic traceability. Currently only the claim
files and git history provide this — the audit log makes it queryable.

---

### Unicode homoglyph detection
**Current state:** The sanitizer catches zero-width chars, bidi overrides, and
invisible codepoints but not look-alike substitutions (е vs e, а vs a, etc.).

**Goal:** Add a homoglyph detection pass that flags text containing characters from
confusable Unicode ranges that could be used to disguise instruction patterns.

**Implementation sketch:**
- Use Unicode confusables data (`unicodedata` + a confusables list)
- Flag strings where skeleton form (confusable-normalized) matches an instruction
  pattern even if the raw string doesn't
- Add test cases to the injection corpus

---

## Usability

### `secure-wiki query "question"`
**Current state:** The wiki can be ingested and listed but not queried. The
`load_for_context()` function in `read/hygiene.py` produces a safe context block
but nothing consumes it interactively.

**Goal:** A query command that loads the wiki as nonce-delimited context and answers
a question through a model.

**Implementation sketch:**
```
secure-wiki query "What is LLM01?"
secure-wiki query "What sources cover MITRE ATLAS?" --min-trust trusted
```
- Calls `load_for_context()` to build the context block
- Constructs: system = context system_note + task instruction; user = question
- Calls the review model (or a separate `QUERY_MODEL` env var)
- Prints the answer; optionally cites claim IDs

**Why it matters:** Closes the knowledge-base loop — the wiki becomes a queryable
asset, not just a storage artefact.

---

### URL ingestion with shallow crawl
**Current state:** `secure-wiki ingest <url>` fetches a single page.

**Goal:** Add `--depth N` to follow links up to N hops from the seed URL, ingesting
each page as a separate source with its own provenance and trust level.

**Implementation sketch:**
- `--depth 1` follows all links on the seed page (same domain only by default)
- `--domain-lock` flag restricts crawl to the seed domain
- Each fetched page gets its own `SourceRef` with the page URI
- Respects `robots.txt`

---

### `--dry-run` flag on ingest
**Goal:** Show what would be committed/quarantined without writing anything to the
wiki repo. Useful for previewing before ingesting a large or unknown source.

**Implementation sketch:**
- Skip `store.save_claim()` / `store.save_quarantined()` calls
- Print `[DRY RUN]` prefix on each gate outcome line
- No git commits made

---

## Portfolio / red-teaming

### OWASP / MITRE ATLAS mapping document
**Goal:** A standalone `docs/security-mapping.md` that walks through each attack
vector in the injection corpus, explains where and why it's stopped, and maps it
to OWASP LLM Top 10 and MITRE ATLAS techniques.

**Why it matters:** Makes the red-teaming intent immediately legible to anyone
reading the repo. High value for consulting presentations with minimal effort.

**Structure:**
- One section per attack vector
- Sub-sections: attack description, how it's constructed, which gate stops it,
  why that gate catches it, OWASP + ATLAS references
- Final section: threat model summary and trust boundary diagram (ASCII)

---

### Extended injection corpus
**Goal:** Add attack vectors not currently covered.

| ID | Attack | Expected gate |
|----|--------|---------------|
| 09 | Unicode homoglyph substitution in instruction pattern | sanitizing |
| 10 | Multi-ingestion attack (benign first pass, payload second) | write_gate / consistency |
| 11 | Adversarial frontmatter injection (payload in YAML keys) | sanitizing |
| 12 | Encoding chain (URL-encoded inside base64) | sanitizing |
| 13 | Claim supersession abuse (fake supersedes pointer) | write_gate / provenance |

---

### Benchmark mode
**Goal:** `secure-wiki benchmark` runs the full injection corpus against a live
model pair and reports which gates fired, how long each stage took, and whether
any attacks slipped through.

**Implementation sketch:**
- Runs each corpus case through the real pipeline (no mocks)
- Compares actual gate decision against `expected_stop_gate` in manifest
- Reports pass/fail per case + timing
- Useful for comparing model pairs (e.g. llama3.1:8b+mistral vs qwen2.5+phi4)
