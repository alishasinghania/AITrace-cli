## AITrace Core Architecture (Draft)

This document outlines the high-level architecture for the new AITrace engine,
informed by `_ref_discovery/aibommaker` and `_ref_metadata/AIMMX`, but implemented
as a modern, cohesive Python core.

### Goals

- **Surface Discovery**: Scan manifests and code imports to identify AI/ML
  dependencies and cloud providers.
- **Deep Inspection**: Extract structured metadata from model files, weights,
  and configuration artefacts.
- **Semantic Mapping**: Trace data flow from inputs to model inference and
  generate Mermaid.js diagrams representing the architecture.
- **Governance**: Evaluate analysis results against `policy.yaml` and fail
  the build on violations.
- **Outputs**: Produce CycloneDX 1.7, SPDX 3.0, and a custom Enterprise Risk
  Report.

### Core Packages

- `core.models`
  - Data classes that represent:
    - Repositories, files, components, dependencies.
    - AI models, datasets, providers, and services.
    - Findings and risk signals.
    - AIBOM: the unified “AI Bill of Materials” model.

- `core.discovery`
  - **`surface.py`**
    - Manifest scanners for:
      - `requirements.txt`, `pyproject.toml`, `poetry.lock`
      - `package.json`, `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`
      - Other common SBOM/lock formats when needed.
    - Static import scanners for:
      - Python (`import` / `from ... import ...`)
      - Simple heuristics for JS/TS (`import`, `require`).
    - Classification helpers that label dependencies as:
      - AI libraries (e.g., OpenAI, Anthropic, Cohere, Google Generative AI,
        Mistral, Hugging Face, LangChain, LlamaIndex, vLLM, etc.).
      - Cloud provider SDKs (AWS, GCP, Azure, etc.).

  - **`deep.py`**
    - File-system scanners that locate:
      - Model weights (`.pt`, `.bin`, `.safetensors`, `.onnx`, `.pb`, etc.).
      - Configuration files (`config.json`, `model_config.json`, YAML configs).
      - Tokenizers and vocabularies.
    - Lightweight metadata extraction:
      - Hugging Face-style configs (architecture, hidden size, attention heads…).
      - Basic tensor statistics when safe (e.g., size, dtype, approximate layer
        counts) – implemented defensively to avoid heavy imports.

  - **`semantic.py`**
    - AST-based analysis for Python code that:
      - Locates calls into AI/LLM libraries and model inference entrypoints.
      - Traces simple dataflow patterns from inputs → preprocessing →
        model invocation → postprocessing.
      - Emits Mermaid.js `flowchart` diagrams that summarize these flows at a
        function or module level.

- `core.engine`
  - Orchestrates the full pipeline, inspired by the detector orchestration logic
    in `analyzer.js` and the GitHub-centric metadata extraction in `AIMMX`:
    - Accepts a local repository path (future: GitHub URL abstraction).
    - Runs surface discovery, deep inspection, and semantic mapping.
    - Normalizes results into a single `AIBOM` instance plus a list of findings.
  - Implements a simple plugin-style interface so that new detectors can be
    added without changing the core pipeline.

- `core.policy`
  - Loads and validates `policy.yaml`.
  - Enforces rules such as:
    - Allowed / denied licenses for dependencies and models.
    - Approved model identifiers or providers.
    - Risk thresholds (e.g., maximum tolerated risk score).
  - Produces a `PolicyReport` with:
    - Individual rule evaluations.
    - Overall pass/fail decision used by the CLI to set the exit code.

- `core.exporters`
  - **`cyclonedx.py`**
    - Serializes the internal `AIBOM` model into a CycloneDX 1.7 JSON document.
    - Focuses on core fields (components, relationships, licenses, hashes) with
      room for later extension.
  - **`spdx.py`**
    - Serializes `AIBOM` into an SPDX 3.0-like JSON document.
  - **`risk_report.py`**
    - Builds an “Enterprise Risk Report” summarizing:
      - Key AI components and models.
      - Data flows and Mermaid diagrams.
      - Detected risks and policy violations.
    - Output can be JSON or Markdown; the CLI will select via flags.

- `core.cli_support`
  - Shared helpers for the Typer CLI:
    - Repository loading utilities.
    - Pretty-printing and Rich-style console helpers (optional).
    - Path and environment handling.

### CLI (Typer)

- Entry module (outside of `core` but using it) – e.g. `src/AITRACE_CLI.PY`:
  - `aitrace scan PATH_OR_URL --policy policy.yaml --format cyclone-dx --format spdx --format risk-report --out out/`
    - Performs full analysis, evaluates policy, and writes selected outputs.
    - Exits with non-zero code when **any** policy violation is marked as
      `fail_build: true`.
  - `aitrace init-policy`:
    - Generates a starter `policy.yaml` with reasonable defaults and comments.

This document is intentionally high-level; individual modules will contain
docstrings describing their responsibilities and extension points.

