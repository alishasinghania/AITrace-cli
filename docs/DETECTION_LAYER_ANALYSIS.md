# AI Component Detection Layer Analysis

AITrace CLI uses a **multi-layer approach** to detect AI components. This document maps each detection layer to the codebase and evaluates how well they combine.

---

## Detection Layer Analysis

### 1. Dependency Detection

**Files:** `src/core/discovery/surface.py`

**Logic:** Parses dependency manifests to extract declared AI/LLM/agent packages. Only packages in predefined maps (`AI_PACKAGES`, `AGENT_PACKAGES`, `MCP_PACKAGES`, `CLOUD_PACKAGES`, `AGENT_TOOL_PACKAGES`) are surfaced as components.

**Implementation:**

```python
# _parse_requirements: regex REQ_LINE_RE matches pkg[extras] specifier version
def _parse_requirements(path: Path) -> Iterable[Tuple[str, Optional[str]]]:
    for line in _read_lines(path):
        m = REQ_LINE_RE.match(line)  # ^\s*(?P<name>[...])(?:\[...])?\s*(==|>=|...)?\s*(?P<version>...)?
        if m:
            yield m.group("name").lower(), m.group("version")

# _parse_pyproject: tomllib (3.11+) or regex for [project].dependencies
# _parse_package_json: dependencies, devDependencies, peerDependencies, optionalDependencies

# _scan_manifests: aggregates requirements.txt, pyproject.toml, package.json
# Produces Component objects; ALL deps are stored, but findings are only for known AI packages
```

**Manifests covered:** `requirements.txt`, `pyproject.toml`, `package.json`

**Component extraction:** All parsed dependencies become `Component` objects in the AIBOM. Findings are generated only when the package name matches a key in `AI_PACKAGES`, `AGENT_PACKAGES`, etc.

---

### 2. Import Detection

**Files:** `src/core/discovery/surface.py` (`_scan_python_imports`), `src/core/detectors/shadow_ai_detector.py`

**Logic (surface.py):** Walks all Python files, parses AST, and collects `ast.Import` and `ast.ImportFrom` nodes. Uses `_normalize_import_to_ai_package()` to map module paths to known package keys (e.g. `google.generativeai` → `google-generativeai`, `git` → `gitpython`).

```python
def _scan_python_imports(root: Path) -> Set[str]:
    all_known = {**AI_PACKAGES, **AGENT_PACKAGES, **MCP_PACKAGES, **CLOUD_PACKAGES, **AGENT_TOOL_PACKAGES}
    for path in root.rglob("*.py"):
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    normalized = _normalize_import_to_ai_package(alias.name)
                    if normalized:
                        imported.add(normalized)
            elif isinstance(node, ast.ImportFrom) and node.module:
                normalized = _normalize_import_to_ai_package(node.module)
                if normalized:
                    imported.add(normalized)
```

**Logic (shadow_ai_detector.py):** Scans for imports of AI API modules (`openai`, `anthropic`, etc.) and compares against declared dependencies. Flags packages used in code but not in manifests.

**Config/string reference (import-like):** `src/core/detectors/config_reference_detector.py` scans `.py`, `.yaml`, `.json`, `.env`, etc. for:
- API URL patterns (`api.openai.com`, `api.anthropic.com`, etc.)
- Model ID patterns (`"gpt-4"`, `"claude-3.5-sonnet"`, etc.)
- Provider keys (`"provider": "openai"`)

These are merged with `imported_modules` in surface discovery and can create inferred components when a provider is referenced but not in manifests.

---

### 3. API Call Detection

**Files:**
- `src/core/discovery/semantic.py` — LLM inference calls, agent patterns, dataflow
- `src/core/detectors/rag_detector.py` — RAG (embeddings, vector stores, retrieval, LLM)
- `src/core/detectors/agent_detector.py` — Agent frameworks (LangChain, CrewAI, AutoGen, etc.)
- `src/core/detectors/shadow_ai_detector.py` — Ungoverned API usage
- `src/core/detectors/huggingface_detector.py` — `from_pretrained`, pipeline, model loading
- `src/core/detectors/config_reference_detector.py` — Config/string references

**Logic (semantic.py):** AST visitor identifies LLM inference calls by:
- Call chain must contain a known provider (`openai`, `anthropic`, `cohere`, etc.) or
- Generic targets (`chat`, `complete`, `create`, `invoke`, `generate`, `messages`) require chain context (`SEMANTIC_LLM_CHAIN_REQUIRED`)
- Blocklists avoid FPs: `init`, `embed`, `asyncio`, `redis`, `pn.`, `gmail`, etc.

```python
def _is_llm_inference_call(target: str, chain: List[str]) -> Optional[str]:
    if t in LLM_TARGET_BLOCKLIST: return None
    if any(bl in chain_str for bl in LLM_CHAIN_BLOCKLIST): return None
    if chain_set & LLM_KNOWN_PROVIDERS: return ".".join(chain)
    if t in SEMANTIC_LLM_TARGETS and chain_set & SEMANTIC_LLM_CHAIN_REQUIRED: return ".".join(chain)
    return None
```

**Logic (rag_detector.py):** Matches AST call targets/chains against:
- `EMBEDDING_PATTERNS`, `VECTOR_STORE_PATTERNS`, `RETRIEVAL_PATTERNS`, `LLM_PATTERNS`
- RAG = embedding + vector store + LLM; partial patterns (e.g. embedding+LLM) also supported
- `RAG_FRAMEWORK_PATTERNS` (llama_index, haystack, ragas, etc.) boost evidence

**Logic (agent_detector.py):** Framework-specific patterns (`create_react_agent`, `StateGraph`, `CrewAgent`, `AssistantAgent`, etc.) with chain guards to avoid generic matches.

---

### 4. Model Artifact Detection

**Files:** `src/core/discovery/deep.py`, `src/core/detectors/huggingface_detector.py`

**Logic (deep.py):** File discovery for model binaries and configs.

```python
MODEL_EXTENSIONS = {".pt", ".bin", ".safetensors", ".onnx", ".pb"}
CONFIG_FILENAMES = {"config.json", "model_config.json"}

# .bin exclusions: AssetManifest, build artifacts, HNSW index files
# MODEL_BIN_EXCLUDE = {"build", "web", "assets", "assetmanifest"}
# MODEL_BIN_NAME_EXCLUDE = {"data_level0.bin", "length.bin", "link_lists.bin", "header.bin"}
```

**Logic (huggingface_detector.py):** Combines:
- AST: `AutoModel`, `AutoTokenizer`, `from_pretrained`, `StableDiffusionPipeline`, etc.
- File discovery: same extensions; `config.json` for model configs
- Confidence: high if AST + files; medium if AST only; low if files only

---

## Architecture Assessment

### Strengths of the Current Implementation

1. **Layered design:** Surface (deps + imports + config refs), deep (models + MCP), semantic (flows + LLM calls), plus modular detectors (RAG, agents, Shadow AI, HuggingFace).

2. **Config/string fallback:** `config_reference_detector` catches metadata-only usage (e.g. aibommaker) where imports and calls are absent.

3. **Blocklists to reduce FPs:** `LLM_TARGET_BLOCKLIST`, `LLM_CHAIN_BLOCKLIST`, `EMBEDDING_EVIDENCE_BLOCKLIST`, and similar filters avoid common non-AI patterns.

4. **Shadow AI detection:** Explicitly checks for API usage without declared dependencies.

5. **Framework-aware:** `FRAMEWORK_PACKAGE_NAMES` exempts framework repos from Shadow AI.

6. **Path ignore:** `get_ignore_paths()` (e.g. via `aitrace.yaml`) plus built-in skips (venv, tests, etc.) focus detection on production code.

### Potential Detection Gaps

1. **Model format:** `.gguf` is not in `MODEL_EXTENSIONS` (Ollama, llama.cpp).
2. **Dynamic imports:** `__import__()`, `importlib.import_module()` are not tracked.
3. **Import aliases:** `import openai as oai`; calls to `oai.ChatCompletion.create` may not map cleanly to provider.
4. **JavaScript/TypeScript:** Detection is Python-only; no npm/JS-based AI usage.
5. **pyproject optional groups:** Only `[project].dependencies`; `[project.optional-dependencies]` and tool-specific sections partially covered (shadow_ai has poetry), surface.py may miss some.

### Recommended Improvements (Only If Clearly Beneficial)

**1. Add `.gguf` to model artifact detection**

- **Why:** Widely used format for local LLMs (Ollama, llama.cpp).
- **Where:** `src/core/discovery/deep.py`, `src/core/detectors/huggingface_detector.py`
- **Change:** Add `.gguf` to `MODEL_EXTENSIONS`.

**2. (Optional) Dynamic import detection**

- **Why:** Some code uses `__import__("openai")` or `importlib.import_module()`.
- **Trade-off:** More complex AST analysis, modest gain; many repos use normal imports.
- **Verdict:** Defer unless real-world misses are observed.

### Cases Where the Existing Implementation Should Be Kept Unchanged

1. **Whitelist-based dependency matching:** Only reporting known AI packages is intentional; generic deps stay out of the AIBOM.

2. **Chain context for generic targets:** Requiring provider or framework context for `create`, `invoke`, `chat` avoids FPs from generic APIs.

3. **Separate RAG/agent detectors:** RAG (embedding + vector + LLM) vs agents (orchestration) are different; separate detectors are appropriate.

4. **Config reference as supplemental signal:** Used to infer components; not intended to replace import/call analysis.

5. **Deep discovery model exclusions:** Excluding `.bin` in `build/`, `assets/`, HNSW index files correctly filters non-model binaries.
