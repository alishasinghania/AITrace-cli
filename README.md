# AITrace CLI

**The AI Bill of Materials & Security Platform for Production Systems.** AITrace delivers comprehensive visibility into every AI component, data flow, and risk surface in your codebase—before it reaches production.

---

## Why AITrace?

Modern applications ship with dozens of hidden AI dependencies: LLM SDKs, embedding models, vector stores, agent frameworks, and MCP servers. Without traceability, you're flying blind. AITrace gives you:

- **Complete AI inventory** — Every dependency, model reference, and framework at a glance
- **Data flow visibility** — See exactly where user input, database output, and secrets flow into AI calls
- **Supply chain assurance** — Track model origins from Hugging Face, local artifacts, and fine-tuned weights
- **Policy enforcement** — Gate deployments on licenses, models, and risk thresholds
- **Industry-standard SBOMs** — CycloneDX 1.7 and SPDX 3.0 with machine-learning-model support

---

## How It Works

AITrace runs a multi-stage analysis pipeline that moves from surface dependencies to deep semantic understanding:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         AITrace Analysis Pipeline                            │
└─────────────────────────────────────────────────────────────────────────────┘

  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
  │   SURFACE    │     │    DEEP      │     │   SEMANTIC   │
  │  Discovery   │────▶│  Inspection  │────▶│   Mapping    │
  └──────────────┘     └──────────────┘     └──────────────┘
        │                      │                      │
        ▼                      ▼                      ▼
  • Manifests             • Model artifacts       • LLM call patterns
    (requirements,          (.pt, .safetensors,   • RAG flows
     pyproject,              .gguf, .ggml)        • Agent orchestrators
     package.json)        • MCP server configs   • Embedding pipelines
  • Import analysis       • Config files         • Data flow nodes
  • Config/string refs    • HuggingFace loaders
  • Optional deps

                              │
                              ▼
  ┌──────────────────────────────────────────────────────────────────────────┐
  │                    Parallel Analysis (Post-Discovery)                     │
  ├─────────────┬─────────────┬─────────────┬─────────────┬───────────────────┤
  │ Data Flow   │ Sensitive   │ Model       │ Prompt      │ Architecture      │
  │ Analyzer    │ Exposure   │ Supply      │ Injection   │ Inference         │
  │             │ Detector   │ Chain       │ Detector   │ (RAG, Agents, MCP) │
  └─────────────┴─────────────┴─────────────┴─────────────┴───────────────────┘
        │              │              │              │              │
        └──────────────┴──────────────┴──────────────┴──────────────┘
                                      │
                                      ▼
                    ┌─────────────────────────────────────┐
                    │  Unified AIBOM + Findings + Risk    │
                    │  • 5-dimension risk scoring         │
                    │  • Policy evaluation                │
                    │  • CycloneDX / SPDX / Risk Report   │
                    └─────────────────────────────────────┘
```

### Stage 1: Surface Discovery

Scans dependency manifests and source code to build the initial component inventory:

- **Manifest parsing** — `requirements.txt`, `pyproject.toml` (incl. optional-dependencies), `package.json`, `setup.py`
- **Import analysis** — AST-based detection of AI/LLM SDKs (OpenAI, Anthropic, etc.), agent frameworks (LangChain, CrewAI), RAG stacks (LlamaIndex, ChromaDB), and MCP packages
- **Dynamic imports** — Handles `__import__()` and `importlib.import_module()` for late-loaded modules
- **Config references** — Detects API URLs, provider keys, and model IDs in YAML, JSON, and source files

### Stage 2: Deep Inspection

Dives into the filesystem and configuration:

- **Model artifacts** — Identifies `.pt`, `.safetensors`, `.gguf`, `.ggml`, `.bin` and other model weights
- **MCP servers** — Parses MCP configuration to discover server packages and commands
- **Hugging Face usage** — AST patterns for `from_pretrained`, `hf_hub_download`, `snapshot_download`

### Stage 3: Semantic Mapping

Maps high-level AI architecture patterns:

- **LLM inference** — Deduplicated call patterns (e.g. `openai.ChatCompletion.create`, `anthropic.messages.create`)
- **RAG flows** — Embedding models → vector stores → retrieval → LLM
- **Agent orchestrators** — LangGraph, CrewAI, AutoGen patterns
- **Data flow graphs** — Semantic nodes with example files and occurrence counts

### Stage 4: Risk & Compliance

Runs specialized analyzers and policy checks:

- **Data flow analysis** — Taint-tracks user input, DB, files, env vars → LLM sinks
- **Sensitive exposure** — Variables (`password`, `api_key`, `token`) flowing into inference
- **Model supply chain** — Source classification (trusted org, remote URL, local) and risk levels
- **Prompt injection** — User-controlled strings reaching prompts without sanitization
- **5-dimension risk scoring** — External AI Exposure, Data Exposure, Execution Risk, Architecture Complexity, Missing Controls
- **Policy evaluation** — License, model, and risk rules with build fail on violation

---

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Initialize a policy file (optional but recommended)
./run.sh init-policy

# Scan a repository
./run.sh scan . --out-dir aitrace-out
```

Or run directly:

```bash
PYTHONPATH=src python3 -m aitrace_cli scan . --out-dir aitrace-out
```

---

## Output Formats

| Format       | Output                     | Description                                           |
|-------------|----------------------------|-------------------------------------------------------|
| `cyclonedx` | `aitrace-cyclonedx.json`   | CycloneDX 1.7 SBOM with AI components, models, evidence |
| `spdx`      | `aitrace-spdx.json`        | SPDX 3.0–style SBOM                                  |
| `risk-json` | `aitrace-risk-report.json` | Enterprise Risk Report (JSON)                         |
| `risk-md`   | `aitrace-risk-report.md`   | Human-readable Risk Report                            |
| `mermaid`   | `aitrace-component-diagram.mmd` | AI component Mermaid diagram                  |

Findings are written as `aitrace-findings.json` when risk reports are generated.

```bash
./run.sh scan . --format cyclonedx --format risk-md --out-dir reports
```

---

## CycloneDX AI BOM

The CycloneDX output produces a rich SBOM tailored for AI systems:

- **Root component** — Repo metadata (name, version, purl) from `pyproject.toml` or `package.json`
- **Libraries** — LLM SDKs (OpenAI, Anthropic, Google AI, etc.) with usage evidence and detection metadata
- **Machine-learning models** — API models (gpt-4o, claude-3-opus, gemini-1.5-pro), Hugging Face models, and local binary artifacts
- **Frameworks** — RAG, AI Agents, embedding pipelines with evidence locations
- **Dependencies graph** — Root → all AI components; models → transformers where applicable

---

## Configuration (`aitrace.yaml`)

Place `aitrace.yaml` in your repo root to customize scanning:

```yaml
ignore_paths:
  - examples
  - tests
  - docs
  - experimental
```

Files under these directories are excluded from AST and AI analysis.

---

## Policy Governance (`policy.yaml`)

Create `policy.yaml` to enforce:

- **Licenses** — Allowed/denied SPDX identifiers; build fails on violations
- **Models** — Approved/denied model names
- **Model sources** — Trusted/verified Hugging Face organizations
- **Risk** — Max allowed severity; build fails if exceeded

```bash
./run.sh init-policy   # Generates policy.yaml with defaults
./run.sh scan . -p policy.yaml
```

---

## Requirements

- Python 3.9+
- `typer` ≥ 0.12.3
- `PyYAML` ≥ 6.0.2

---

## Use Cases

| Use case | AITrace delivers |
|---------|------------------|
| **Security & Compliance** | Full AI inventory, data flow maps, sensitive exposure alerts |
| **Supply Chain** | Model origins, trusted org verification, binary artifact detection |
| **CI/CD** | Policy gates, risk thresholds, SBOM generation for artifact attestation |
| **Audit & Reporting** | CycloneDX BOM, risk reports, Mermaid diagrams for stakeholders |
| **Architecture Review** | RAG vs direct LLM, agent frameworks, embedding pipelines at a glance |

---

*Built for teams who ship AI to production.*
