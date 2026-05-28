# Secure LLM-Wiki

A persistent, agentically maintained knowledge wiki following Andrej Karpathy's pattern — built
from the ground up to resist **Indirect Prompt Injection** and **source poisoning**.

Instead of re-scanning raw documents on every query (classic RAG), an LLM maintains a persistent,
linked Markdown wiki: knowledge is compiled once and then curated. The security challenge is the
hard part — a crafted source must never reach the wiki persistently and poison later sessions.

---

## Security model in one sentence

Untrusted input (a source) must never reach a channel that is later treated as trusted (the wiki).
Every layer enforces this trust boundary.

## Pipeline

```
Source → [1] Ingestion      (data/instruction separation + sanitizing)
       → [2] Extraction     (atomic claims + provenance)
       → [3] Trust-Tiering  (weakest level propagates)
       → [4] Adversarial Review (independent second model)
       → [5] Write-Gate     (lint + consistency → commit | quarantine | escalate)
       → [6] Wiki-Store     (Markdown + metadata, Git-versioned)
       → [7] Read-Time Hygiene
```

## Project structure

```
secure-llm-wiki/
├── README.md
├── pyproject.toml                 # src layout, pytest pythonpath
├── requirements.txt
├── environment.yml                # Conda environment definition
├── .env.example                   # LLM config template
├── src/secure_wiki/
│   ├── models.py                  # Claim/SourceRef/TrustLevel — single source of truth ✅
│   ├── llm_client.py              # Ollama / Anthropic provider abstraction ✅
│   ├── ingestion/
│   │   ├── sanitizer.py           # Obfuscation detection ✅
│   │   └── prompts.py             # Nonce-delimiters + data/instruction separation ✅
│   ├── extraction/
│   │   └── extractor.py           # Claim extraction via LLM ✅
│   ├── trust/                     # Trust-tiering (TODO)
│   ├── review/
│   │   └── adversarial.py         # 4-eyes adversarial review ✅
│   ├── gate/write_gate.py         # Gate orchestration (stub)
│   ├── store/                     # Markdown + metadata + Git (TODO)
│   └── read/                      # Read-time hygiene (TODO)
├── tests/
│   ├── test_injection_corpus.py   # Regression suite ✅ (sanitizing layer green)
│   └── injection_corpus/
│       ├── manifest.json          # 8 cases + expected stop-gates + OWASP/ATLAS mappings
│       └── 0X_*.txt               # crafted attack sources
└── wiki_data/
    ├── pages/                     # committed wiki pages
    └── quarantine/                # pending / quarantined claims
```

✅ = implemented and passing · stub/TODO = not yet implemented

## Status

The foundation is running: data model, sanitizer, prompt separation, LLM extraction, and
adversarial review are implemented. The injection corpus is wired and the regression suite is
green at the sanitizing layer (`8 passed`). Trust-tiering, write-gate, wiki store, and
read-time hygiene remain as documented stubs.

## Build order

1. **Priority 1** — data/instruction separation + sanitizing ✅; claim provenance ✅
2. **Priority 2** — trust-tiering (TODO); adversarial review ✅
3. **Priority 3** — write-gate + quarantine; Git versioning; read-time hygiene

## Setup

```bash
# Create and activate the conda environment
conda env create -f environment.yml
conda activate llm-wiki

# Configure LLM provider
cp .env.example .env
# Edit .env — defaults to Ollama with llama3.1:8b (extraction) + mistral (review)
source .env

# Run the regression suite (no API key needed for sanitizer tests)
pytest -q
```

The sanitizer and regression tests run without any LLM connection. Extraction and adversarial
review require a running Ollama instance (`ollama serve`) or an `ANTHROPIC_API_KEY`.

## Red-teaming & portfolio

The injection corpus (`tests/injection_corpus/`) is part of the deliverable: every attack in the
manifest is mapped to the gate where it must be stopped, plus to **OWASP LLM Top 10** and
**MITRE ATLAS**. This makes the project usable as a reference for AI red-teaming and consulting.

New attack vectors are added as an additional case in the manifest plus a source file — the
regression suite ensures later changes don't weaken the hardening.
