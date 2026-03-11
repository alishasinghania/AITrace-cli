# AITrace CLI

**Enterprise AI security scanning for the modern stack.** AITrace analyzes repositories to build an AI Bill of Materials (AIBOM), detect architecture patterns, trace data flows to LLMs, and produce a comprehensive risk assessment—all from a single scan.

---

## What AITrace Does

AITrace answers the questions every AI-enabled application team needs: *What AI components are we using? Where does data flow to models? What are our exposure and governance risks?*

- **AI Bill of Materials** — Inventories AI/ML dependencies, models, embeddings, vector stores, agent frameworks, and cloud providers
- **Architecture Discovery** — Classifies patterns: RAG, AI Agents, embedding pipelines, and direct LLM inference
- **AI Data Flow Analysis** — Taint-tracks untrusted data (user input, DB, files, HTTP) from sources to LLM sinks
- **Sensitive Data Exposure** — Flags variables like passwords and API keys flowing into inference calls
- **Model Supply Chain** — Maps where models are loaded (Hugging Face, local, fine-tuned, etc.)
- **Prompt Injection Risks** — Identifies user-controlled strings reaching prompts without sanitization
- **5-Dimension Risk Scoring** — Quantifies risk across External AI Exposure, Data Exposure, Execution Risk, Architecture Complexity, and Missing Controls
- **Policy Governance** — Enforces license, model, and risk policies; fails the build on violations

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

Use `--format` / `-f` to select outputs (default: all):

| Format       | Output                     | Description                                   |
|-------------|----------------------------|-----------------------------------------------|
| `cyclonedx` | `aitrace-cyclonedx.json`   | CycloneDX 1.7–style SBOM (JSON subset)       |
| `spdx`      | `aitrace-spdx.json`        | SPDX 3.0–style SBOM (JSON subset)            |
| `risk-json` | `aitrace-risk-report.json` | Enterprise Risk Report (JSON)                 |
| `risk-md`   | `aitrace-risk-report.md`   | Human-readable Risk Report (Markdown)         |
| `mermaid`   | `aitrace-component-diagram.mmd` | AI component Mermaid diagram            |

Findings are also written as `aitrace-findings.json` when risk reports are generated.

**Example:**

```bash
./run.sh scan . --format risk-md --format mermaid --out-dir reports
```

---

## Enterprise Risk Report

The risk report includes:

- **Risk score** (0–100) with level: Minimal / Low / Medium / High
- **5-dimension breakdown** — External AI Exposure, Data Exposure to LLMs, Execution Risk, Architecture Complexity, Missing AI Security Controls
- **AI Data Flow Analysis** — Taint flows from user input, DB, files, HTTP to LLM sinks (OpenAI, Anthropic, etc.)
- **Sensitive exposures** — Variables (password, api_key, token, …) flowing into inference
- **Model supply chain** — Model sources, versions, and locations
- **Prompt injection risks** — Unsanitized user data reaching prompts
- **Architecture types** — RAG, AI Agents, Embedding Pipeline, Direct LLM
- **MCP servers** — MCP server configurations and packages
- **Policy evaluation** — Pass/fail against `policy.yaml`

---

## Configuration (`aitrace.yaml`)

Place `aitrace.yaml` in your repo root to customize scanning:

```yaml
# Path segments to skip during AI analysis (reduces false positives)
ignore_paths:
  - examples
  - tests
  - docs
  - experimental
  - integrations
  - packs
  - demo
```

Files under these directories are excluded from AST scanning and AI analysis. Defaults match the list above if no config is present.

---

## Policy Governance

Create a `policy.yaml` to enforce:

- **Licenses** — Allowed/denied SPDX identifiers; build fails on violations
- **Models** — Approved/denied model names
- **Risk** — Max allowed severity; build fails if exceeded

```bash
./run.sh init-policy   # Generates policy.yaml with defaults
./run.sh scan . -p policy.yaml
```

---

## Requirements

- Python 3.9+
- `typer>=0.12.3`
- `PyYAML>=6.0.2`

---

## Use Cases

- **Security & Compliance** — Understand AI dependencies and data flows before production
- **Supply Chain** — Track AI model origins and third-party AI services
- **CI/CD** — Gate deployments on policy and risk thresholds
- **Audit & Reporting** — Generate SBOMs and risk reports for stakeholders
- **Architecture Review** — Visualize AI components and flows with Mermaid diagrams
