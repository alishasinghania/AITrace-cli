# AITrace — Attack Path Analysis and Exploit Synthesis for AI Applications

Traces user-controlled data through AI framework call chains across files and generates working exploit payloads from confirmed attack paths. Static analysis — no running application needed.

Supports LangChain · LangGraph · AutoGen · CrewAI · Semantic Kernel · LlamaIndex · Haystack · RAG pipelines · MCP servers · OpenAI / Anthropic / Cohere / Vertex AI SDKs · ChromaDB · Pinecone · FAISS and more.

---

## What it does

- **Traces attack paths** — Follows user input, env vars, and external data through AI framework calls across modules (not single-file grep)
- **Confirms reachability** — Cross-file call-graph analysis marks which paths actually reach LLM, agent, code-exec, or SQL sinks
- **Synthesizes exploits** — With `--exploit`, emits codebase-specific PoC payloads aimed at confirmed sinks, plus static CONFIRMED / LIKELY / UNCERTAIN verdicts
- **Surfaces AI stack context** — Inventories LLM SDKs, agents, RAG, vector stores, and MCP configs so the path has a clear target map
- **One HTML report** — Walk findings and (optional) exploit payloads in the browser after each run

Optional: CycloneDX / SPDX AI BOM and Mermaid architecture diagram via `-f`.

---

## Installation

**Requirements:** Python 3.9+ · No telemetry · Core analysis makes no external API calls

```bash
# Recommended
pipx install aitrace-cli
# or
uv tool install aitrace-cli

aitrace --help
```

From source:

```bash
git clone https://github.com/alishasinghania/AITrace-cli
cd AITrace-cli
pip install -e .
```

---

## Usage

```bash
# Scan a local repo — writes aitrace-report.html and opens it
aitrace scan ./my-app

# Scan a remote GitHub repo directly (shallow clone, no setup needed)
aitrace scan https://github.com/owner/repo
aitrace scan https://github.com/owner/repo --exploit

# Generate PoC payloads from confirmed paths (+ RAG poison docs when RAG detected)
aitrace scan ./my-app --exploit

# Headless / CI — no browser
aitrace scan ./my-app --no-open

# Write to a specific directory
aitrace scan ./my-app -o ./results

# Optional machine-readable outputs
aitrace scan ./my-app -f cyclonedx -f spdx -f mermaid

# Policy gate — exits code 1 on violation (use in CI)
aitrace scan ./my-app --policy policy.yaml --no-open

# Write findings JSON + architecture graph
aitrace scan ./my-app --verbose
```

---

## Output files

By default, all files are written into the **scanned repository root**. Use `-o` / `--out-dir` to choose another directory.

| File | When |
|------|------|
| `aitrace-report.html` | Always (primary deliverable) |
| `aitrace-exploits.json` | `--exploit` |
| `aitrace-rag-poison-payload.txt` | `--exploit` + RAG detected |
| `aitrace-cyclonedx.json` | `-f cyclonedx` |
| `aitrace-spdx.json` | `-f spdx` |
| `aitrace-component-diagram.mmd` | `-f mermaid` |
| `aitrace-risk-report.md` | `-f risk-md` |
| `aitrace-findings.json` · arch graph | `--verbose` |

---

## How it works

AITrace runs four stages in sequence against your codebase:

### 1. Discovery
Scans package manifests (`requirements.txt`, `pyproject.toml`, `package.json`), Python imports, MCP config files (`.cursor/mcp.json`, `claude_desktop_config.json`), and model artifacts to build a complete inventory of AI components — LLM SDKs, agent frameworks, vector stores, embedding models, and MCP servers.

### 2. Path analysis
Builds a cross-file call graph by parsing every Python file with AST analysis. Sources (FastAPI/Flask routes, WebSocket handlers, Celery tasks, CLI entrypoints) are traced forward through function calls across module boundaries until they reach a sink — an LLM prompt construction, `cursor.execute()`, `eval()`, or agent tool invocation. Each path is classified as confirmed, likely, or uncertain based on whether sanitization or filtering is detected on the way.

On top of taint tracing, a pattern analyzer checks for structural vulnerability shapes regardless of data flow: unbounded tool permissions, direct LLM output to `exec()`, hardcoded credentials, missing output validation, and others (PAT-001 through PAT-023).

### 3. Exploit synthesis (`--exploit`)
For each confirmed or likely path, generates a codebase-specific proof-of-concept payload targeting the exact sink and variable names found in your code. Each payload comes with a static verification verdict (CONFIRMED / LIKELY / UNCERTAIN) explaining what evidence was found. For RAG pipelines, also generates adversarial documents designed to survive vector similarity search, with insertion code for Chroma, Pinecone, FAISS, Weaviate, and Qdrant.

### 4. Report
Writes a single self-contained `aitrace-report.html` with collapsible security findings grouped by vulnerability type, MCP server analysis, exploit payloads gated behind a "Security Team Only" toggle, and a color-coded architecture diagram. Opens in your default browser automatically.

---

## Policy gate

Optional governance check for CI — not a substitute for path analysis:

```bash
aitrace init-policy
aitrace scan . --policy policy.yaml --no-open
```

Exit code `1` on violation. Example GitHub Actions step:

```yaml
- name: AITrace policy gate
  run: aitrace scan . --policy policy.yaml --no-open
```
