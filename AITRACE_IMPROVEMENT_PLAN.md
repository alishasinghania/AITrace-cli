# AITrace CLI — Detection Engine and Risk Reporting Improvement Plan

**Goal:** Upgrade detection, architecture analysis, and risk reporting while preserving current architecture and avoiding duplicate implementations.

---

## STEP 1 — Repository Analysis

### 1.1 Existing Structure

| Layer | Modules | Purpose |
|-------|---------|---------|
| **Entry** | `aitrace_cli.py`, `AITRACE_CLI.PY` | CLI (Typer), output dispatch |
| **Engine** | `engine.py` | Orchestrates discovery + analyzers → `AnalysisResult` |
| **Discovery** | `surface.py`, `deep.py`, `semantic.py` | Manifests, models, semantic flows |
| **Detectors** | `rag_detector`, `agent_detector`, `mcp_detector`, `huggingface_detector`, `shadow_ai_detector`, `config_reference_detector` | AST-based architecture inference |
| **Analyzers** | `dataflow_analyzer`, `sensitive_data_detector`, `model_supply_chain_analyzer`, `prompt_injection_detector` | Taint, sensitive data, model origins, prompt injection |
| **Architecture** | `architecture_inference.py` | Runs detectors, merges into `ArchitectureResult` |
| **Risk** | `risk_scoring.py` | Five-dimension risk score |
| **SBOM** | `cyclonedx.py`, `spdx.py` | CycloneDX 1.7 AI BOM, SPDX 3.0 |
| **Export** | `risk_report.py`, `component_diagram.py`, `provider_summary.py` | Risk report, Mermaid, provider summary |

### 1.2 Current Pipeline Stages

```
1. discover_surface()     → components from manifests + imports
2. discover_deep()        → model artifacts (.pt, .bin, .safetensors, etc.), MCP configs
3. discover_semantic()    → DataFlowGraph[] (RAG, Direct LLM, Embedding Pipeline), llm_usage
4. infer_architecture()   → ArchitectureResult (RAG, Agents, MCP, HuggingFace, Shadow AI)
5. analyze_dataflows()   → user_input/env/file → LLM sinks (taint)
6. analyze_sensitive_exposures()   → password/api_key/token → LLM sinks
7. analyze_model_supply_chain()    → HuggingFace, URLs, local; trusted vs unknown
8. analyze_prompt_injection()      → user_input→agent/LLM; agent tools; sanitization
9. classify_repository()  → application | library | framework
10. compute_risk_score()  → 5 dimensions, 0–100
11. Export               → CycloneDX, SPDX, risk-json, risk-md, Mermaid
```

### 1.3 Existing Analyzers (Detail)

| Analyzer | File | Current Capabilities | Gaps |
|----------|------|----------------------|------|
| **Data Flow** | `dataflow_analyzer.py` | Taint: request/input/env/file→LLM sinks; sanitization (escape, guardrails, etc.); per-function scoping | No cross-file taint; no API endpoints; no user→API→retriever→LLM path |
| **Sensitive Exposure** | `sensitive_data_detector.py` | Sensitive var names (password, api_key, token)→LLM sinks | No os.environ/dotenv/config/AWS source detection; no “reaches external API” flag |
| **Model Supply Chain** | `model_supply_chain_analyzer.py` | HuggingFace, torch.load, safetensors; trusted orgs; policy.yaml | No SHA256 hashes; no `.pth` in MODEL_EXTENSIONS |
| **Prompt Injection** | `prompt_injection_detector.py` | Dataflow→risk; agent.invoke(user_input) with tools; sanitization; HIGH_RISK_TOOLS | Good sanitization logic; could add more sanitizers (e.g. guardrails.validate) |
| **Architecture Inference** | `architecture_inference.py` | Runs RAG, Agents, MCP, HuggingFace, Shadow AI; merges evidence | Shallow; no full graph; no attack paths |

### 1.4 Existing Detectors

| Detector | Current Coverage | Gaps |
|----------|------------------|------|
| **RAG** | Embeddings, vector stores, retrieval, LLM; LlamaIndex, Haystack, RAGAS | No document loaders (PDFLoader, SimpleDirectoryReader, etc.); no “external source → RAG poisoning” flag |
| **Agent** | LangChain, LangGraph, CrewAI, AutoGen, Semantic Kernel | Adequate |
| **MCP** | .cursor/mcp.json, mcp.json | Adequate |
| **HuggingFace** | from_pretrained, pipelines, model files | Adequate |
| **Shadow AI** | API usage not in manifests | Adequate |
| **Config Reference** | API URLs, model IDs in config | Used by surface discovery |

### 1.5 Discovery Modules

| Module | Output | Gaps |
|--------|--------|------|
| **surface** | Components from manifests; imports; config refs | Adequate |
| **deep** | ModelArtifact (.pt, .bin, .safetensors, .onnx, .pb, .gguf, .ggml); MCP | No .pth; no SHA256 hashes |
| **semantic** | DataFlowGraph[] (clustered flows), llm_usage | High-level semantic nodes; not a unified graph; no user_input/api_endpoint/retriever nodes |

### 1.6 Risk Scoring

- **Dimensions:** External AI (25), Data Exposure (25), Execution Risk (20), Architecture (15), Missing Controls (15)
- **Output:** `RiskScoreResult` with total, risk_level, dimensions, contributing_factors
- **Gap:** No explicit `ai_security_score` JSON summary; no `top_risks` list for report

### 1.7 Identified Weaknesses

| Weakness | Severity |
|----------|----------|
| No AI attack path analyzer | High |
| No full architecture graph (networkx) | High |
| Sensitive exposure: no dotenv/config/DB credential sources | Medium |
| Model detection: no SHA256, no .pth | Medium |
| RAG: no document loader detection; no RAG poisoning flag | Medium |
| Taint: intra-procedural only (no cross-file) | Medium |
| Risk score: no `top_risks` / JSON summary shape | Low |
| High-risk tools: good coverage; could add more | Low |

---

## STEP 2 — Detection Improvement Plan

### 2.1 Context-Aware Prompt Injection

- **Exists:** `prompt_injection_detector.py` — dataflow, sanitization, agent tools
- **Action:** Extend `SANITIZATION_PATTERNS` / `SANITIZATION_NAMES` with:
  - `guardrails.validate`, `guardrails.apply`
  - `input_validation`, `validate_input`, `clean_input`
  - `prompt_guard`, `moderation`
- **Action:** When `sanitized=True`, keep finding but mark as mitigated (already done)
- **Action:** Reduce FPs by requiring chain context for generic `invoke`/`run`

### 2.2 Secret Leakage into LLM Prompts

- **Exists:** `sensitive_data_detector.py` — var names (password, api_key, token)
- **Action:** Add source patterns for:
  - `os.environ`, `os.getenv`
  - `dotenv.load_dotenv`, `python-dotenv`
  - Config: `yaml.safe_load`, `json.load` (config files)
  - `boto3.client('secretsmanager').get_secret_value`
- **Action:** Track if sink is external LLM (openai, anthropic, etc.) → flag `external_provider=True`, severity critical
- **Action:** Avoid blocking `max_tokens`, `completion_tokens` (already in blocklist)

### 2.3 Agent Tool Abuse

- **Exists:** `prompt_injection_detector.py` — agent.invoke(user_input) with tools
- **Action:** Extend `HIGH_RISK_TOOLS` with `code_interpreter`, `python_repl`, `bash`, `shell`, `execute`
- **Action:** Add finding type `agent_tool_abuse` when user_input→agent with high-risk tool
- **Action:** Integrate with attack path analyzer when created

### 2.4 RAG Attack Surface

- **Exists:** `rag_detector.py`, `semantic.py`
- **Action:** Add document loader patterns: `PDFLoader`, `SimpleDirectoryReader`, `CSVLoader`, `WebBaseLoader`, `UnstructuredFileLoader`
- **Action:** If loader uses external URL or user-uploaded path → add `possible_rag_poisoning` finding
- **Action:** RAG detector already has embeddings, vector stores, retrieval; extend evidence for loaders

### 2.5 AI Architecture Reconstruction

- **Exists:** `semantic.py` (DataFlowGraph), `component_diagram.py` (Mermaid)
- **Action:** Create new module `architecture_graph.py` that builds a unified graph:
  - Nodes: user_input, api_endpoint, document_loader, embedding_model, vector_db, retriever, llm_provider, agent, tool, database
  - Edges: from semantic flows + dataflow analyzer + RAG/agent detectors
  - Use networkx internally
  - Export: JSON graph, Mermaid (integrate with `component_diagram.py`)

### 2.6 AI Attack Path Discovery

- **Does not exist**
- **Action:** Create `ai_attack_path_analyzer.py`:
  - Consume architecture graph
  - Detect chains: User Input → Prompt → LLM → Tool → Database
  - Output: `{"type": "ai_attack_path", "severity": "critical", "path": [...], "description": "..."}`
  - Integrate with risk report and risk scoring

### 2.7 Model Supply Chain Verification

- **Exists:** `model_supply_chain_analyzer.py`, `discovery/deep.py`
- **Action:** In `deep.py`, add SHA256 hash computation for model files (`.bin`, `.safetensors`, `.pt`, `.pth`, `.gguf`, `.onnx`)
- **Action:** Add `.pth` to `MODEL_EXTENSIONS`
- **Action:** Store `sha256` in `ModelArtifact.config` or new field
- **Action:** Include hashes in CycloneDX/SPDX export

### 2.8 AI Security Posture Scoring

- **Exists:** `risk_scoring.py` — 5 dimensions, `RiskScoreResult`
- **Action:** Align dimension weights with requested percentages:
  - External AI Exposure: 25%
  - Data Exposure: 25%
  - Execution Risk: 20%
  - Architecture Complexity: 15%
  - Missing Controls: 15%
- **Action:** Add `top_risks: List[str]` derived from contributing_factors
- **Action:** Output shape: `{"ai_security_score": 72, "risk_level": "medium", "top_risks": [...]}`

---

## STEP 3 — Architecture Graph Reconstruction

### 3.1 New Module: `architecture_graph.py`

- **Purpose:** Build unified AI architecture graph from existing discovery + analyzers
- **Inputs:** `AIBOM`, `DataFlowAnalysisResult`, `SemanticDiscoveryResult`, `ArchitectureResult`
- **Node kinds:** `user_input`, `api_endpoint`, `document_loader`, `embedding_model`, `vector_db`, `retriever`, `llm_provider`, `agent`, `tool`, `database`, `model_artifact`
- **Edges:** From semantic flows, dataflow analyzer, RAG detector, agent detector

### 3.2 Graph Structure

- **Internal:** `networkx.DiGraph` with node attributes `kind`, `label`, `file`, `line`
- **Export JSON:** `{"nodes": [...], "edges": [...]}` compatible with D3/vis.js
- **Export Mermaid:** Extend `component_diagram.py` or add `architecture_graph_to_mermaid()` to produce subgraphs for each layer

### 3.3 Compatibility

- Keep `aitrace-component-diagram.mmd` output
- Option: Add `aitrace-architecture-graph.json` and optionally `aitrace-architecture-graph.mmd`

---

## STEP 4 — Attack Path Analysis

### 4.1 New Module: `ai_attack_path_analyzer.py`

- **Input:** Architecture graph from `architecture_graph.py`
- **Logic:** Enumerate paths that match patterns:
  - User Input → Prompt → LLM
  - User Input → Retriever → LLM (RAG injection)
  - User Input → Agent → Tool → Database
  - Embedding → Vector DB (poisoning entry)
- **Output:** `List[AttackPathFinding]` with `type`, `severity`, `path`, `description`
- **Integration:** Add to `AnalysisResult`, include in risk report, feed into risk scoring

### 4.2 Finding Format

```json
{
  "type": "ai_attack_path",
  "severity": "critical",
  "path": ["user_input", "prompt", "llm", "tool", "database"],
  "description": "Prompt injection leading to database access"
}
```

---

## STEP 5 — Improve Prompt Injection Detection

- **Current:** `dataflow_analyzer.py` has `SANITIZATION_PATTERNS`; `prompt_injection_detector.py` uses them
- **Action:** Add `guardrails.validate`, `guardrails.apply`, `moderation`, `input_validation`, `validate_input`, `clean_input`, `html.escape`, `bleach.clean`, `markupsafe.escape` (some already present)
- **Action:** Before flagging vulnerability, check if tainted var passed through sanitization → set `sanitized=True`, mark mitigated
- **Action:** Refactor to share sanitization pattern list between dataflow and prompt_injection (single source of truth)

---

## STEP 6 — Improve Secret Exposure Detection

- **Exists:** `sensitive_data_detector.py` — var names only
- **Action:** Add source patterns:
  - `os.environ`, `os.getenv`, `environ.get`
  - `dotenv.load_dotenv`, `python_dotenv`
  - `yaml.safe_load`, `json.load` (when path suggests config)
  - `boto3.client('secretsmanager').get_secret_value`
- **Action:** Add `external_provider: bool` to `SensitiveExposure` when sink is OpenAI/Anthropic/etc.
- **Action:** If `external_provider=True` and risk=critical → severity critical

---

## STEP 7 — Improve RAG Detection

- **Current:** `rag_detector.py` — embeddings, vector stores, retrieval, LLM
- **Action:** Add document loader patterns: `PDFLoader`, `SimpleDirectoryReader`, `CSVLoader`, `WebBaseLoader`, `UnstructuredFileLoader`, `DirectoryLoader`
- **Action:** If loader uses URL or user-provided path → add `possible_rag_poisoning` finding to findings
- **Action:** Ensure vector stores: Chroma, Pinecone, Weaviate, FAISS (already present)

---

## STEP 8 — Improve Model Detection

- **Current:** `discovery/deep.py` — MODEL_EXTENSIONS = `.pt`, `.bin`, `.safetensors`, `.onnx`, `.pb`, `.gguf`, `.ggml`
- **Action:** Add `.pth` to `MODEL_EXTENSIONS`
- **Action:** Compute SHA256 for model files (use `hashlib.sha256` on file content; for large files, sample or hash metadata)
- **Action:** Store in `ModelArtifact.config["sha256"]` or extend `ModelArtifact` with `sha256: Optional[str]`
- **Action:** Update CycloneDX and SPDX exporters to include hashes

---

## STEP 9 — AI Security Score

- **Current:** `risk_scoring.py` — dimensions already match 25/25/20/15/15
- **Action:** Add `top_risks: List[str]` — e.g. top 5 from `contributing_factors` or from high-severity findings
- **Action:** Ensure JSON output includes `ai_security_score`, `risk_level`, `top_risks`
- **Action:** Add summary block to risk report (risk-md) with score + top risks

---

## STEP 10 — Reporting Improvements

- **Current:** CycloneDX, SPDX, risk-json, risk-md, Mermaid
- **Action:** Extend risk report with:
  1. AI architecture graph (JSON + optional Mermaid)
  2. Attack path findings section
  3. RAG pipeline visualization (from architecture graph or RAG detector)
  4. AI security score summary block
- **Action:** Ensure backward compatibility: same output filenames, additive fields only

---

## STEP 11 — Code Quality

- **No duplicate analyzers:** Extend `dataflow_analyzer`, `sensitive_data_detector`, `prompt_injection_detector`, `model_supply_chain_analyzer`; do not create overlapping modules
- **New modules only where needed:** `architecture_graph.py`, `ai_attack_path_analyzer.py`
- **Reuse:** `_ast_utils`, `should_skip_path`, existing data structures
- **Integration:** All new analyzers called from `engine.py`; results in `AnalysisResult`; exported via `risk_report.py` and CLI

---

## Summary of Improvements

| Area | Action |
|------|--------|
| Prompt injection | Extend sanitization patterns; share with dataflow; mitigate when sanitized |
| Secret exposure | Add os.environ, dotenv, config, AWS sources; flag external LLM sinks |
| Agent tool abuse | Extend HIGH_RISK_TOOLS; add agent_tool_abuse finding |
| RAG detection | Add document loaders; flag possible RAG poisoning |
| Architecture graph | **NEW** `architecture_graph.py` — networkx, JSON + Mermaid |
| Attack path | **NEW** `ai_attack_path_analyzer.py` — uses graph |
| Model detection | Add .pth; SHA256 in deep discovery; include in SBOM |
| Risk score | Add top_risks; ensure JSON shape |
| Reporting | Architecture graph, attack paths, RAG viz, score summary |

---

## Modified Modules (Existing)

| Module | Changes |
|--------|---------|
| `dataflow_analyzer.py` | Extend SANITIZATION_PATTERNS; optional cross-file (future) |
| `sensitive_data_detector.py` | Add env/dotenv/config/AWS sources; external_provider flag |
| `prompt_injection_detector.py` | Extend sanitization; HIGH_RISK_TOOLS; share patterns |
| `model_supply_chain_analyzer.py` | (Optional) integrate SHA256 from ModelArtifact |
| `discovery/deep.py` | Add .pth; SHA256 computation; store in ModelArtifact |
| `detectors/rag_detector.py` | Add document loader patterns |
| `risk_scoring.py` | Add top_risks; ensure output shape |
| `engine.py` | Call architecture_graph, ai_attack_path_analyzer |
| `exporters/risk_report.py` | Add architecture graph, attack paths, RAG viz, score summary |
| `exporters/cyclonedx.py` | Include model SHA256 if present |
| `exporters/spdx.py` | Include model SHA256 if present |
| `models.py` | Optionally add sha256 to ModelArtifact; AttackPathFinding dataclass |

---

## New Modules

| Module | Purpose |
|--------|---------|
| `architecture_graph.py` | Build networkx graph from discovery + analyzers; export JSON + Mermaid |
| `ai_attack_path_analyzer.py` | Detect attack chains from architecture graph; produce AttackPathFinding |

---

## Implementation Order

1. **Model detection** (deep.py) — .pth, SHA256
2. **Sensitive exposure** — env/dotenv/config sources, external_provider
3. **Prompt injection** — sanitization extension, shared patterns
4. **RAG** — document loaders, poisoning flag
5. **Architecture graph** — architecture_graph.py
6. **Attack path analyzer** — ai_attack_path_analyzer.py
7. **Risk score** — top_risks, output shape
8. **Reporting** — integrate all into risk report
