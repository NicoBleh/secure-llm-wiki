# Secure LLM-Wiki

A persistent, agentically maintained knowledge wiki following Andrej Karpathy's pattern — built
from the ground up to resist **Indirect Prompt Injection** and **source poisoning**.

Instead of re-scanning raw documents on every query (classic RAG), an LLM maintains a persistent,
linked Markdown wiki: knowledge is compiled once and then curated. The security challenge is the
hard part — a crafted source must never reach the wiki persistently and poison later sessions.

> **Portfolio context:** This project is designed as a reference artifact for AI red-teaming and
> consulting. The injection corpus maps every attack to its stop-gate, OWASP LLM Top 10, and
> MITRE ATLAS.

---

## Security model in one sentence

Untrusted input (a source) must never reach a channel that is later treated as trusted (the wiki).
Every layer enforces this trust boundary.

## Pipeline

```
Source → [1] Ingestion      data/instruction separation + sanitizing
       → [2] Extraction     atomic claims + provenance (LLM, nonce-delimited)
       → [3] Trust-Tiering  weakest level propagates; URI-pattern registry
       → [4] Adversarial Review  independent second model, 4-eyes principle
       → [5] Write-Gate     sanitizing · provenance · trust · review · consistency
       → [6] Wiki-Store     Markdown + YAML frontmatter, separate git repo
       → [7] Read-Time Hygiene  nonce-delimited context, trust metadata attached
```

All 7 layers are implemented.

## Project structure

```
secure-llm-wiki/
├── README.md
├── pyproject.toml               # src layout, pytest config, secure-wiki entry point
├── requirements.txt
├── environment.yml              # Conda environment (Python 3.10+)
├── .env.example                 # LLM and wiki path config template
├── src/secure_wiki/
│   ├── __main__.py              # CLI: ingest · list · context · query · init ✅
│   ├── models.py                # Claim / SourceRef / TrustLevel — provenance schema ✅
│   ├── llm_client.py            # Ollama + Anthropic provider abstraction, token usage ✅
│   ├── prompts.py               # All system prompts, nonce-delimiter builders ✅
│   ├── ingestion/
│   │   └── sanitizer.py         # Zero-width, bidi, HTML, base64, instruction patterns ✅
│   ├── extraction/
│   │   └── extractor.py         # Claim extraction via LLM, fail-closed JSON parsing ✅
│   ├── trust/
│   │   └── tiering.py           # URI-pattern registry, user rules via trust_rules.yaml ✅
│   ├── review/
│   │   └── adversarial.py       # Independent review model, JSON verdict, fail-closed ✅
│   ├── gate/
│   │   └── write_gate.py        # 5-gate orchestration: commit / quarantine / escalate ✅
│   ├── store/
│   │   ├── wiki_store.py        # Separate git repo, Markdown + frontmatter, roundtrip ✅
│   │   └── embedding_store.py   # Claim embeddings for Gate 5 semantic similarity ✅
│   └── read/
│       └── hygiene.py           # Nonce-delimited context loading with trust metadata ✅
├── tests/
│   ├── test_injection_corpus.py # Sanitizer + full pipeline regression (79 tests total)
│   ├── test_trust_tiering.py
│   ├── test_wiki_store.py
│   ├── test_read_hygiene.py
│   ├── test_cli.py
│   └── injection_corpus/
│       ├── manifest.json        # 8 cases + stop-gates + OWASP LLM Top 10 / MITRE ATLAS
│       └── 0X_*.txt             # Crafted attack sources
└── wiki_data/                   # Separate git repo, created on first run (gitignored here)
    ├── pages/                   # Committed (ACTIVE) claims
    ├── quarantine/              # QUARANTINED / PENDING claims
    └── trust_rules.yaml         # User-editable trust rules
```

## Setup

```bash
# Create and activate a virtual environment (Python 3.10+)
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# Install the package and dev dependencies
pip install -e ".[dev]"

# Configure LLM provider and wiki path
cp .env.example .env
# Edit .env — defaults to Ollama with llama3.1:8b (extraction) + mistral (review)

# Run the test suite (no LLM or wiki repo needed)
pytest -q
```

> **uv users:** `uv venv && uv pip install -e ".[dev]"` — same result, much faster.

## Usage

```bash
# Initialize the wiki data repository
secure-wiki init

# Ingest a single file (interactive trust prompt when --trust is omitted)
secure-wiki ingest path/to/document.txt
secure-wiki ingest path/to/paper.pdf

# Ingest a URL (trust level auto-detected from domain, then confirmed interactively)
secure-wiki ingest https://attack.mitre.org/techniques/T1059

# Ingest an entire folder (trust prompted once for the whole batch)
secure-wiki ingest path/to/docs/
secure-wiki ingest path/to/docs/ --recursive     # include sub-folders

# Override trust level manually (skips the interactive prompt)
secure-wiki ingest report.txt --trust semi-trusted --source-id vendor-advisory-2026

# List committed claims
secure-wiki list

# List quarantined claims (blocked by a gate)
secure-wiki list --quarantine

# Open an interactive Q&A session against the wiki
# Prompts for minimum trust level at startup; type 'exit' to quit
# Token usage (input / output) is shown after each answer
secure-wiki query
secure-wiki query --min-trust trusted            # skip the startup prompt

# Print the raw nonce-delimited context block (for piping into other tools)
secure-wiki context
secure-wiki context --min-trust trusted

# Delete claims (all options ask for confirmation before proceeding)
secure-wiki clear --quarantine                   # remove all quarantined claims
secure-wiki clear --trust untrusted              # remove all claims at a trust level (pages + quarantine)
secure-wiki clear --reset                        # full reset — wipes git repo and all claims (trust_rules.yaml preserved)
secure-wiki clear --reset --keep-history         # same but commits removal instead of wiping the repo
```

### Supported input formats

| Format | Extensions |
|---|---|
| Plain text | `.txt`, `.md`, `.rst`, `.csv` |
| HTML | `.html`, `.htm` (tags and scripts stripped automatically) |
| PDF | `.pdf` (text extracted via pypdf) |

## LLM configuration

| Variable | Default | Purpose |
|---|---|---|
| `LLM_PROVIDER` | `ollama` | `ollama` or `anthropic` |
| `EXTRACTION_MODEL` | `llama3.1:8b` | Model for claim extraction |
| `REVIEW_MODEL` | `mistral` / `claude-sonnet-4-6` | Model for adversarial review — **must differ from EXTRACTION_MODEL** to preserve 4-eyes independence |
| `EMBED_MODEL` | `nomic-embed-text` | Model for Gate 5 semantic similarity (Ollama only) |
| `OLLAMA_HOST` | `http://localhost:11434` | Ollama server URL |
| `ANTHROPIC_API_KEY` | — | Required only for `LLM_PROVIDER=anthropic` |
| `WIKI_DATA_PATH` | `./wiki_data/` | Path to the wiki data git repository |

Token usage (input and output tokens) is reported after every LLM call — in the ingest
summary and after each query answer.

The test suite runs without any LLM connection — all model calls are mocked.

## Security architecture

### Trust boundary
Every pipeline layer enforces a single invariant: untrusted input never reaches a channel treated as trusted. Sources are wrapped in spec-constructed nonce-delimiters before reaching any model. The wiki is loaded with the same pattern — nonce-delimited, with a system note identifying the content as data, not instructions.

### Write-gate (5 checks in sequence)
1. **Sanitizing** — any obfuscation flag → quarantine
2. **Provenance** — source.id, URI, content hash must all be set
3. **Trust-tier** — untrusted claim cannot overwrite established high-trust content
4. **Adversarial review** — independent model checks for manipulation, not correctness
5. **Consistency** — conflict with existing high-trust claims → escalate to human

### 4-eyes principle
Extraction and review use **different models** by default. With Ollama: `llama3.1:8b` (extraction) and `mistral` (review). With Anthropic: `claude-haiku-4-5` (extraction) and `claude-sonnet-4-6` (review). A jailbreak that compromises the extractor must not simultaneously compromise the reviewer.

### Fail-closed
Unparseable LLM responses are treated as failures — empty extraction returns no claims, unparseable review verdict blocks the write. The system never silently passes bad output.

### Adversarial review tuning
The review prompt distinguishes between genuine injection (text that addresses the AI model to change its behavior) and legitimate technical content (code examples, API docs, function references). This prevents false positives on programming documentation while keeping the guard against rule-manipulation attempts and trust-policy overrides.

## Red-teaming & portfolio

The injection corpus (`tests/injection_corpus/`) covers 8 attack vectors, each mapped to:
- The gate where it **must** be stopped
- **OWASP LLM Top 10** category
- **MITRE ATLAS** technique

| Attack | Category | Stop gate | OWASP | ATLAS |
|---|---|---|---|---|
| `01_direct_instruction.txt` | Direct instruction override | sanitizing | LLM01 | AML.T0051 |
| `02_zero_width.txt` | Hidden payload (zero-width chars) | sanitizing | LLM01 | AML.T0051 |
| `03_html_comment.txt` | Hidden payload (HTML comment) | sanitizing | LLM01 | AML.T0051 |
| `04_white_text.txt` | Hidden payload (display:none) | sanitizing | LLM01 | AML.T0051 |
| `05_base64_smuggle.txt` | Hidden payload (base64 block) | sanitizing | LLM01 | AML.T0051 |
| `06_rule_change.txt` | Subtle rule-change attempt | adversarial_review | LLM01 | AML.T0051 |
| `07_overwrite_trusted.txt` | Trust manipulation / overwrite | write_gate | LLM03 | AML.T0020 |
| `08_benign_control.txt` | Control (must pass all gates) | — | — | — |

New attack vectors are added as a manifest entry + source file. The regression suite ensures later changes don't weaken the hardening.
