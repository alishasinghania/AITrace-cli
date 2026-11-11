# AITrace — Attack Path Analysis and Exploit Synthesis for AI Applications

Traces user-controlled data through AI framework call chains **across files**, confirms which paths reach LLM / exec / SQL / MCP sinks, and can synthesize PoC payloads from those paths. Static analysis — no running application needed.

Supports LangChain · LangGraph · AutoGen · CrewAI · Semantic Kernel · LlamaIndex · Haystack · Pydantic AI · DSPy · MCP servers · OpenAI / Anthropic / Cohere / Vertex AI SDKs · ChromaDB · Pinecone · FAISS · Qdrant · guardrails · observability stacks and more.

---

## How it works

![How AITrace finds an attack path](docs/assets/aitrace-architecture-flow.gif)

1. **Discovery** — Inventories AI packages (LLM SDKs, agents, vector stores, embeddings, guardrails, observability, MCP), model artifacts, and MCP server configs.
2. **Pattern analysis** — Flags structural shapes (PAT-001 … PAT-031): unsanitized RAG, PythonREPL/`exec`, SQL execute, RAG upload, MCP tool-return injection, lethal trifecta, secrets in prompts/KB, and more.
3. **Cross-file taint** — Builds a call graph and traces **values** (user input, LLM output, MCP tool args) to sinks. Confirmed payload paths become **FLOW-RCE**, **FLOW-SQL**, **FLOW-LLM**, **FLOW-HTTP**, **FLOW-EMAIL**, **FLOW-RAG**, with hop lists. Matching PAT hits are marked **taint confirmed**.
4. **Report** — Single `aitrace-report.html`: hybrid architecture overview, grouped findings (pattern / path confirmed / LLM verified), taint-path graph, optional exploits.
5. **Optional** — `--verify` (LLM semantic check), `--exploit` (PoC payloads), `--policy` (CI gate including AI controls).

---

## What it does

- **Traces attack paths** — Follows user input, env vars, tool args, and LLM output through AI framework calls across modules (not single-file grep)
- **Confirms reachability** — Value-taint analysis marks which paths actually reach LLM, agent, `exec`, SQL, HTTP, email, or RAG ingest sinks
- **Classifies findings** — `pattern` (shape only) vs `taint_confirmed` (traced hops) vs `llm_verified` (optional `--verify`)
- **Maps the AI stack** — LLM SDKs, agents, RAG, vector stores, MCP servers (including poisoned tool descriptions and hardcoded MCP secrets)
- **Hybrid architecture overview** — Call vs construct edges, trust-boundary sinks, omitted unused APIs; SVG in the HTML report
- **Risk score** — Execution / data / external exposure dimensions, including pattern and taint findings
- **Policy gate** — Licenses, models, severity, plus AI controls (`no_code_execution_tools`, `no_shadow_ai`, `mcp_trust_score_minimum`, `no_user_data_to_external_llm`, `no_hardcoded_credentials`)
- **Synthesizes exploits** — `--exploit` emits codebase-specific PoCs for confirmed sinks (CONFIRMED / LIKELY / UNCERTAIN)
- **Optional LLM verify** — `--verify` after `aitrace configure` (or env / `--secret-ref`); core scan never calls an API

---

## Installation

**Requirements:** Python 3.9+ · No telemetry · Core analysis makes no external API calls

**From source (recommended — latest code):**

```bash
git clone https://github.com/alishasinghania/AITrace-cli
cd AITrace-cli
pip install -e .
```

**LLM verification extra** (only needed for `--verify` / `aitrace configure`):

```bash
pip install -e ".[verify]"
```

**From PyPI:**

```bash
# Install uv (if not already installed)
curl -LsSf https://astral.sh/uv/install.sh | sh   # macOS / Linux
# or: pip install uv

uv tool install aitrace-cli
# or: pipx install aitrace-cli
```

> **Note:** The PyPI release may lag behind the GitHub repo. Install from source to get the latest features.

---

## Usage

```bash
# Scan a local repo — writes aitrace-report.html and opens it
aitrace scan ./my-app

# Scan a remote GitHub repo directly (shallow clone, no setup needed)
aitrace scan https://github.com/owner/repo
aitrace scan https://github.com/owner/repo --exploit

# Generate PoC payloads from confirmed paths
aitrace scan ./my-app --exploit

# Optional LLM verification of selected findings (requires configure or env)
aitrace configure --provider anthropic
aitrace scan ./my-app --verify
aitrace scan ./my-app --dry-run-verify   # show what would be sent, no API call

# Headless / CI — no browser
aitrace scan ./my-app --no-open

# Write to a specific directory
aitrace scan ./my-app -o ./results

# Optional machine-readable outputs
aitrace scan ./my-app -f cyclonedx -f spdx -f mermaid -f risk-md

# Policy gate — exits code 1 on violation (use in CI)
aitrace scan ./my-app --policy policy.yaml --no-open

# Write findings JSON + architecture graph
aitrace scan ./my-app --verbose
```

---

## Policy gate

Optional governance check for CI — not a substitute for path analysis:

```bash
aitrace init-policy
aitrace scan . --policy policy.yaml --no-open
```

Exit code `1` on violation. `init-policy` writes license / model / risk rules plus `ai_controls` (code-exec tools, shadow AI, MCP trust floor, user-data-to-LLM, hardcoded credentials).

Example GitHub Actions step:

```yaml
- name: AITrace policy gate
  run: aitrace scan . --policy policy.yaml --no-open
```

---

## Acknowledgments

Attempts to follow [CycloneDX](https://cyclonedx.org/) 1.7 and [SPDX](https://spdx.dev/) 3.0.1 for optional AI BOM export (`-f cyclonedx`, `-f spdx`) — not a claim of full compliance.

Inspired by the need for AI transparency in software supply chains, and by existing SBOM work that still underspecifies LLM SDKs, agents, RAG pipelines, and MCP servers.

OWASP LLM Top 10 and CWE identifiers on findings are for orientation, not a certified mapping.

---

## Disclaimer

This tool is for security auditing and analysis of systems **you own or have explicit permission** to analyze. Do not run it against repositories or deployments you are not authorized to assess. The authors are not responsible for misuse.

`--exploit` produces proof-of-concept material for confirmed paths in that authorized target. Treat generated payloads as sensitive; do not use them against systems you do not control.

---

## Experimental

This is experimental code. The focus is analyzing AI/LLM application source — attack paths, components, MCP configs — while BOM and AI-SBOM formats are still moving. Optional CycloneDX/SPDX output is a best-effort export, not a guaranteed conformant document.

There is no promise of stable CLI flags, finding IDs, report layout, or complete rule coverage. Formats and detectors will change. If a mature AI BOM generator or scanner later covers this ground, this repo may fold into that work or be archived.

Use it as a research / audit aid, not as a compliance certificate.
