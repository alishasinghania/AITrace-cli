# AITrace

> **An open-source AI security scanner that doesn't just detect vulnerabilities — it proves they're exploitable.**

AITrace scans your codebase to map every AI component, trace data flows into LLMs, detect security vulnerabilities, and generate working proof-of-concept attack payloads from static analysis alone. No runtime required.

---

<!-- Demo recording — replace with your GIF or MP4 -->
<!-- ![AITrace Demo](assets/demo.gif) -->

---

```
$ aitrace scan ./my-app --exploit

Wrote 3 exploit payload(s) to aitrace-exploits.json.

════════════════════════════════════════════════════════════════════════
  ⚠  AITrace exploit payloads — AUTHORIZED SECURITY TESTING ONLY
════════════════════════════════════════════════════════════════════════

[CRITICAL] Direct prompt injection via user input → anthropic.messages.create
  Target: app/chat.py:47   CVSS: 9.3

[CRITICAL] 'db_password' exfiltration via OpenAI API
  Target: app/chat.py:31   CVSS: 9.3

Static verification:
  ✔ CONFIRMED  [95% confidence]  Direct prompt injection
    + No sanitization on source→sink path
    + f-string interpolation into prompt detected
    + External AI provider — data leaves network boundary

RAG pipeline detected (Chroma + OpenAIEmbeddings)
Wrote 3 poison variants → aitrace-rag-poison-payload.txt
```

---

## Installation

```bash
git clone https://github.com/alishasinghania/AITrace-cli
cd AITrace-cli
pip3 install -e .
```

On macOS, pip installs scripts to `~/Library/Python/3.x/bin` which may not be on your PATH. If `aitrace` is not found after install, run:

```bash
echo 'export PATH="$HOME/Library/Python/3.9/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

Then verify:

```bash
aitrace --help
```

Alternatively, use the included `run.sh` without any PATH changes:

```bash
./run.sh scan . --out-dir aitrace-out
```

**Requirements:** Python 3.9+ · No external API calls · No telemetry

---

## Usage

```bash
# Standard scan — 5 output files, browser report opens automatically
aitrace scan ./my-app

# Generate exploit payloads + static verification + RAG poison docs
aitrace scan ./my-app --exploit

# Policy enforcement — exits code 1 on violation (use in CI)
aitrace scan ./my-app --policy policy.yaml

# Debug mode — also writes raw JSON + architecture graph
aitrace scan ./my-app --verbose
```

---

## Architecture

```
  ┌──────────────────────────────────────────────────────────────────┐
  │                        Analysis Pipeline                          │
  ├─────────────────┬──────────────────┬───────────────────────────── ┤
  │  SURFACE        │  DEEP            │  SEMANTIC                    │
  │  · manifests    │  · model files   │  · LLM call patterns         │
  │  · AST imports  │  · MCP configs   │  · RAG flows                 │
  │  · config refs  │  · HuggingFace   │  · agent orchestrators       │
  └────────┬────────┴────────┬─────────┴──────────────┬──────────────┘
           └─────────────────┴────────────────────────┘
                                      │
  ┌───────────────────────────────────▼──────────────────────────────┐
  │                       Security Analysis                           │
  │  Taint Tracker · Sensitive Exposure · Prompt Injection · MCP     │
  └───────────────────────────────────┬──────────────────────────────┘
                                      │
  ┌───────────────────────────────────▼──────────────────────────────┐
  │                    Exploit & Verification                         │
  │  Exploit Synthesizer · Static Verifier · RAG Poison Simulator    │
  └───────────────────────────────────┬──────────────────────────────┘
                                      │
              Risk Score · AI SBOM · HTML Report · Policy Gate
```

---

## What It Does

**AI Bill of Materials** — CycloneDX 1.7 and SPDX 3.0 SBOMs covering every LLM SDK, embedding model, vector store, agent framework, and MCP server in your codebase.

**Data Flow Taint Tracking** — AST-based analysis traces user input, env vars, and file reads into LLM sinks. Sanitization-aware.

**MCP Trust Graph** — Scans MCP tool `description` fields for prompt-injection patterns. Assigns trust scores (0–100) and emits CRITICAL findings when triggered.

**Exploit Synthesizer (`--exploit`)** — Generates purpose-built PoC payloads per flow type:

| Flow | Payload | CVSS |
|------|---------|------|
| `user_input → LLM` | Direct instruction override | 9.3 |
| `env var → LLM` | Variable-targeted extraction | 7.5–9.3 |
| `RAG pipeline` | Knowledge base poisoning | 8.8 |
| `Agent + tools` | Tool-response hijack | 9.3 |

**Static Finding Verifier** — Checks each payload against the source code to determine CONFIRMED / LIKELY / UNCERTAIN without touching a running server.

**RAG Poison Simulator** — Generates adversarial documents designed to survive vector similarity search. Includes Chroma, Pinecone, FAISS, Weaviate, and Qdrant insertion code.

**5-Dimension Risk Scoring** — External Exposure · Data Exposure · Execution Risk · Architecture Complexity · Missing Controls. Policy enforcement with CI exit code 1 on violation.

**Interactive HTML Report** — Self-contained dashboard with risk bars, findings cards, MCP trust scores, and architecture diagram. Auto-opens after every scan.

---

## Output Files

| File | When |
|------|------|
| `aitrace-report.html` | Always |
| `aitrace-risk-report.md` | Always |
| `aitrace-cyclonedx.json` | Always |
| `aitrace-spdx.json` | Always |
| `aitrace-component-diagram.mmd` | Always |
| `aitrace-exploits.json` | `--exploit` |
| `aitrace-rag-poison-payload.txt` | `--exploit` + RAG detected |
| `aitrace-risk-report.json` · `aitrace-findings.json` · arch graph | `--verbose` |

---

## Policy Enforcement

```bash
aitrace init-policy        # generates policy.yaml with defaults
aitrace scan . --policy policy.yaml
```

```yaml
risk:
  max_severity: high
  fail_build: true
models:
  denied: [gpt-3.5-turbo]
model_sources:
  trusted_orgs: [google, microsoft, huggingface]
```

---

*Built for security engineers who need to prove risk, not just report it.*

---

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run a quick smoke scan against this repo
PYTHONPATH=src python3 -m aitrace_cli scan . --out-dir aitrace-out
```
