# AI Component Detection Security Review

**Reviewer:** Senior Security Engineer  
**Scope:** AITrace-CLI detection logic vs. industry best practices and aibommaker case study  
**Date:** March 2025

---

## 1. Detection Mechanisms in aibommaker

### 1.1 aibommaker Repository Profile

**Note:** aibommaker is a model card generation repository, not an AI component detection tool. It contains:
- `modelcards/` – JSON/YAML model cards for OpenAI, Anthropic, Google, Mistral, Cohere, etc.
- Python scripts that use **stdlib only** (json, re, urllib, datetime, os)
- **No** requirements.txt, pyproject.toml, or setup.py
- **No** direct AI SDK imports (`openai`, `anthropic`, `google.generativeai`)
- AI provider names exist only as **string literals** in MODELS dicts (e.g., `{"provider": "openai", ...}`)

### 1.2 What AITrace Detects When Scanning aibommaker

| Detection Mechanism | Result | Reason |
|--------------------|--------|--------|
| Surface (manifest) | 0 components | No requirements.txt / pyproject.toml |
| Surface (imports) | 0 AI imports | Only stdlib imports (json, re, urllib) |
| Deep (model files) | 0 models | No .pt, .safetensors, config.json |
| Semantic (LLM patterns) | 0 | No AST call chains to LLM APIs |
| RAG / Agents / HF / Shadow AI | Not detected | No relevant AST patterns |

### 1.3 Detection Gap: String/Config References

aibommaker references AI providers only in:
- String literals: `"provider": "openai"`, `"api_url": "https://api.openai.com"`
- URLs: `https://platform.openai.com`, `https://ai.google.dev/docs`
- Model names: `"gpt-4"`, `"claude-3.5-sonnet"`, `"gemini-1.5-pro"`

**AITrace does not currently detect:**
- AI provider/model names in string literals
- API URLs in configuration or code
- YAML/JSON config files with model provider references

---

## 2. AITrace-CLI Detection Mechanisms (Current)

### 2.1 Surface Discovery (`discovery/surface.py`)

| Strategy | Implementation | Scope |
|----------|----------------|-------|
| **Dependency scanning** | requirements.txt, package.json | Root only |
| **Import pattern detection** | AST walk for `import X` / `from X import` | First token of module name |

**AI_PACKAGES checked:** openai, anthropic, cohere, google-generativeai, vertexai, mistralai, transformers, diffusers, langchain, llama-index, vllm, litellm  
**Missing:** google (generic), replicate, together, fireworks, groq, perplexity

### 2.2 Deep Discovery (`discovery/deep.py`)

| Strategy | Implementation | Scope |
|----------|----------------|-------|
| **Model weight detection** | File extension (.pt, .bin, .safetensors, .onnx) | All files |
| **Config parsing** | config.json, model_config.json (HuggingFace-style) | Root + subdirs |

**Gap:** No pyproject.toml [project] parsing for dependency extraction in deep discovery.

### 2.3 Semantic Discovery (`discovery/semantic.py`)

| Strategy | Implementation | Scope |
|----------|----------------|-------|
| **AST call chain analysis** | Call targets (chat, create, invoke, embed, etc.) + chain context | All .py files |
| **LLM pattern detection** | Requires chain to contain provider keywords | Strict |

### 2.4 Modular Detectors

| Detector | Mechanism | Evidence |
|----------|-----------|----------|
| **RAG** | AST: embedding + vector store + retrieval + LLM patterns | Call chain matching |
| **AI Agents** | AST: LangChain, LangGraph, CrewAI, AutoGen, Semantic Kernel | Framework-specific patterns |
| **MCP** | Config: .cursor/mcp.json, mcp.json | JSON parsing |
| **HuggingFace** | AST + file scan: from_pretrained, pipeline, .pt/.safetensors | Call + extensions |
| **Shadow AI** | Manifest vs. code: used but not declared | Import + call chain |

---

## 3. Weaknesses in AITrace-CLI

### 3.1 Detection Gaps (False Negatives)

| Gap | Impact | Example |
|-----|--------|---------|
| **Import aliasing** | Miss `import openai as oai` → `oai.ChatCompletion.create()` | Chain starts with `oai`, not `openai` |
| **Dynamic imports** | Miss `__import__("openai")`, `importlib.import_module()` | No AST match |
| **google vs google.generativeai** | `import google` alone not in AI_PACKAGES | Partial Google usage missed |
| **pyproject.toml [project] dependencies** | Surface only does regex; no TOML parser | Complex dependency specs missed |
| **Poetry/Pipenv** | Limited poetry match; no Pipfile | Declared deps undercounted |
| **String/model name references** | No detection of model IDs in strings | aibommaker-style metadata |
| **Config files** | No .env, config.yaml, .env.local for API keys/providers | Runtime config missed |
| **JavaScript/TS** | Python only | @anthropic-ai/sdk, openai, etc. |
| **Replicate, Together, Groq, Perplexity** | Not in AI_PACKAGES | Newer providers missed |

### 3.2 Sources of False Positives

| Source | Impact | Example |
|--------|--------|---------|
| **Generic "create"/"invoke"** | Match non-LLM code | redis.pipeline, tree.create_node |
| **"chat" in chain** | UI components | pn.chat.ChatMessage (Panel) |
| **"embed"** | Non-embedding | url.encode, base64.b64encode |
| **Agent patterns** | Generic task APIs | api_instance.create_agent_task |
| **Blocklist incomplete** | New false positive patterns | Product-specific helpers |

### 3.3 Precision Issues

- **RAG:** Requires embedding + vector + LLM; partial setups (embedding-only) not classified
- **Agent:** Many framework-specific patterns; newer frameworks (e.g., AutoGen 2) may be missed
- **Confidence:** Binary high/medium/low; no scoring or evidence strength

---

## 4. Recommended Improvements

### 4.1 High Priority

1. **Import aliasing:** Resolve aliases and use them when analyzing call chains  
2. **Extend AI_PACKAGES:** Add replicate, together, fireworks, groq, perplexity, google (with submodule checks)  
3. **Config/string reference detection:** Scan for API URLs and model IDs in strings  
4. **Pyproject parsing:** Use `tomllib` (3.11+) or `toml` for robust dependency extraction  

### 4.2 Medium Priority

5. **Prompt template detection:** Detect PromptTemplate, ChatPromptTemplate, f-strings with `{variable}` in LLM call args  
6. **Embedding-only / vector-only:** Classify as "Partial RAG" or "Embedding pipeline"  
7. **Dynamic import handling:** Track `__import__` and `importlib.import_module` for common AI module names  

### 4.3 Lower Priority

8. **JavaScript/TypeScript:** Extend for package.json + JS/TS AST  
9. **Confidence scoring:** Evidence-weighted confidence  
10. **Plugin architecture:** Allow custom detectors and pattern sets  

---

## 5. Example Detection Rules

### 5.1 Extended AI Package Map

```python
# Add to discovery/surface.py AI_PACKAGES
AI_PACKAGES: Dict[str, str] = {
    # ... existing ...
    "replicate": "Replicate",
    "together": "Together AI",
    "fireworks": "Fireworks AI",
    "groq": "Groq",
    "perplexity": "Perplexity",
    "google": "Google AI (generic)",  # import google; google.generativeai
}
```

### 5.2 String Literal / URL Reference Detection

```python
# New: config_reference_detector.py
AI_API_URL_PATTERNS = [
    (r"api\.openai\.com", "openai"),
    (r"api\.anthropic\.com", "anthropic"),
    (r"generativelanguage\.googleapis\.com", "google-generativeai"),
    (r"api\.cohere\.(ai|com)", "cohere"),
    (r"api\.mistral\.ai", "mistralai"),
    (r"api\.replicate\.com", "replicate"),
]

def _scan_string_refs(content: str) -> Set[str]:
    """Find AI provider references in string literals and URLs."""
    found = set()
    for pattern, provider in AI_API_URL_PATTERNS:
        if re.search(pattern, content, re.I):
            found.add(provider)
    # Model ID patterns: gpt-4, claude-3, gemini-1.5
    if re.search(r'["\']?(gpt-4|gpt-3\.5|claude-3|gemini-1\.5|o1-)(mini|flash|pro)?["\']?', content):
        found.add("openai")  # or anthropic/google based on pattern
    return found
```

### 5.3 Import Alias Resolution

```python
# In _ast_utils.py or semantic discovery
def _get_import_aliases(tree: ast.AST) -> Dict[str, str]:
    """Map alias -> real module. e.g. {'oai': 'openai'}."""
    aliases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                real = alias.name.split(".")[0]
                asname = alias.asname or real
                aliases[asname.lower()] = real.lower()
        elif isinstance(node, ast.ImportFrom) and node.module:
            real = node.module.split(".")[0]
            for alias in node.names:
                asname = (alias.asname or alias.name).lower()
                aliases[asname] = real.lower()
    return aliases

# When visiting Call nodes, resolve chain[0] via aliases
# e.g. chain = ['oai', 'ChatCompletion', 'create'] -> resolve oai -> openai
```

### 5.4 google.generativeai Import Handling

```python
# In surface _scan_python_imports - handle multi-level imports
# from google.generativeai import x -> add "google-generativeai" 
# import google.generativeai -> add "google-generativeai"

def _normalize_import_to_ai_package(module: str) -> Optional[str]:
    """Map import path to AI_PACKAGES key."""
    parts = module.lower().split(".")
    if len(parts) >= 2 and parts[0] == "google":
        if "generativeai" in parts or "genai" in parts:
            return "google-generativeai"
        if "cloud" in parts and "aiplatform" in parts:
            return "vertexai"
    first = parts[0] if parts else ""
    if first in AI_PACKAGES:
        return first
    return None
```

---

## 6. Code Snippets to Implement Improvements

### 6.1 String/Config Reference Detector (New Module)

```python
# src/core/detectors/config_reference_detector.py
"""Detect AI provider references in config files and string literals."""

import re
from pathlib import Path
from typing import Set, Tuple

REFERENCE_PATTERNS = [
    (re.compile(r"api\.openai\.com", re.I), "openai"),
    (re.compile(r"api\.anthropic\.com", re.I), "anthropic"),
    (re.compile(r"generativelanguage\.googleapis\.com", re.I), "google-generativeai"),
    (re.compile(r"api\.cohere\.(ai|com)", re.I), "cohere"),
    (re.compile(r"api\.mistral\.ai", re.I), "mistralai"),
]

def detect_config_references(repo_root: Path) -> Set[Tuple[str, str]]:
    """Returns set of (provider, file_path)."""
    found: Set[Tuple[str, str]] = set()
    for path in repo_root.rglob("*"):
        if not path.is_file() or path.suffix not in (".py", ".yaml", ".yml", ".json", ".env", ".toml"):
            continue
        if any(p in path.parts for p in {"venv", ".venv", "node_modules", ".git"}):
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for pat, provider in REFERENCE_PATTERNS:
            if pat.search(content):
                found.add((provider, str(path.relative_to(repo_root))))
    return found
```

### 6.2 Improved Pyproject Parsing

```python
# In discovery/surface.py - add pyproject dependency extraction
def _parse_pyproject_dependencies(path: Path) -> Iterable[Tuple[str, Optional[str]]]:
    """Extract [project] dependencies from pyproject.toml using proper parsing."""
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return
    # Use tomllib for Python 3.11+
    try:
        import tomllib
        data = tomllib.loads(content)
    except ImportError:
        import toml
        data = toml.loads(content)
    deps = data.get("project", {}).get("dependencies", [])
    for dep in deps:
        if isinstance(dep, str):
            # Parse "package>=1.0" or "package[extra]==1.0"
            name = dep.split("[")[0].split(">=")[0].split("==")[0].split("<")[0].strip()
            if name and not name.startswith("$"):
                version = None  # Could extract from specifier
                yield name.lower(), version
```

### 6.3 RAG: Partial Pattern Classification

```python
# In rag_detector.py - add partial patterns
if has_embed and has_llm and not has_vector:
    return DetectionResult(
        component="Embedding + LLM (Partial RAG)",
        confidence="medium",
        evidence=evidence,
        details={"detected": True, "has_vector_store": False, ...},
    )
if has_vector and has_llm and not has_embed:
    return DetectionResult(
        component="Vector Store + LLM (Partial RAG)",
        confidence="medium",
        ...
    )
```

---

## 7. Summary

| Area | Current | Improved |
|------|---------|----------|
| **Manifest parsing** | requirements.txt, package.json, regex pyproject | + tomllib/toml, poetry, Pipfile |
| **Import detection** | First token only | + Alias resolution, google.generativeai |
| **Config/string refs** | None | + API URLs, model IDs in strings |
| **AI package coverage** | ~15 providers | + Replicate, Together, Groq, Perplexity |
| **RAG classification** | Full RAG only | + Partial (embedding+LLM, vector+LLM) |
| **False positive reduction** | Blocklist | + Stricter chain context, plugin overrides |

Implementing these changes would improve AITrace's coverage for repos like aibommaker (metadata-heavy, no runtime SDK) and reduce both false negatives and false positives across typical AI application repositories.
