"""
Generate a Mermaid.js diagram showing AI architecture in layered format.

Follows AI SBOM tool conventions (ProtectAI, Endor Labs):
- Logical layers: Application → Agents → LLM Providers, RAG, Vector DBs, Tools, etc.
- Clear component relationships
- Only AI-relevant components (excludes flask, requests, logging, etc.)
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from ..models import AIBOM, Component, ComponentType

if TYPE_CHECKING:
    from ..architecture_inference import ArchitectureResult

# ---------------------------------------------------------------------------
# Blocklist: generic infra never shown in AI diagram
# ---------------------------------------------------------------------------
_DIAGRAM_BLOCKLIST = frozenset({
    "flask", "django", "fastapi", "requests", "httpx", "aiohttp",
    "logging", "json", "markdown", "yaml", "toml",
    "pytest", "pytest-", "black", "ruff", "mypy", "pre-commit",
    "typing", "dataclasses", "typing_extensions",
    "numpy", "pandas", "scipy",  # generic data; keep if ML-specific
    "setuptools", "pip", "wheel", "build",
})

# ---------------------------------------------------------------------------
# Layer categories — components assigned to ONE primary layer
# ---------------------------------------------------------------------------
# LLM Providers (API SDKs + local inference)
LLM_PROVIDERS = frozenset({
    "openai", "anthropic", "cohere", "google-generativeai", "vertexai",
    "mistralai", "litellm", "ollama", "replicate", "together", "fireworks",
    "fireworks-ai", "groq", "ai21", "aleph-alpha-client", "aleph_alpha",
    "vllm", "perplexity",
})

# Local ML (transformers, diffusers — load model artifacts)
LOCAL_ML = frozenset({"transformers", "accelerate", "diffusers", "vllm"})

# Agent / Orchestration frameworks
AGENT_FRAMEWORKS = frozenset({
    "langchain", "langchain-community", "langchain-core", "langchain_core",
    "langgraph", "crewai", "autogen", "semantic-kernel", "semantic_kernel",
    "haystack", "haystack-ai", "haystack_ai", "smolagents", "marvin",
    "superagi", "babyagi", "agentpy", "agixt",
})

# RAG / Retrieval frameworks
RAG_FRAMEWORKS = frozenset({
    "llama-index", "llama-index-core", "llama_index_core",
    "gpt-index", "gpt_index", "haystack", "haystack-ai", "haystack_ai",
    "ragas", "ragstack",
})

# Vector databases
VECTOR_DATABASES = frozenset({
    "chromadb", "pinecone", "pinecone-client", "weaviate", "weaviate-client",
    "qdrant-client", "qdrant_client", "pymilvus", "milvus",
    "faiss-cpu", "faiss-gpu", "faiss", "pgvector", "redisvl",
    "elasticsearch", "vespa", "pyvespa",
})

# Embedding providers (overlap with LLM; same SDKs often provide both)
EMBEDDING_PROVIDERS = frozenset({
    "openai", "anthropic", "cohere", "voyageai", "vertexai",
    "sentence-transformers", "instructor", "instructor-embedding",
})

# External tools used by agents
AGENT_TOOLS = frozenset({
    "duckduckgo-search", "duckduckgo_search", "playwright",
    "gitpython", "selenium", "beautifulsoup4", "bs4",
})

# Cloud SDKs (AWS, GCP, Azure)
CLOUD_SDKS = frozenset({
    "boto3", "google-cloud", "google-cloud-aiplatform", "azure-ai",
    "azure-core", "azure-identity",
})

# Normalized sets for membership (name uses underscores; sets use hyphens)
def _norm(s: str) -> str:
    return s.lower().replace("-", "_")

def _norm_set(s: frozenset) -> frozenset:
    return frozenset(_norm(x) for x in s)

_LLM_N = _norm_set(LLM_PROVIDERS)
_LOCAL_ML_N = _norm_set(LOCAL_ML)
_AGENT_N = _norm_set(AGENT_FRAMEWORKS)
_RAG_N = _norm_set(RAG_FRAMEWORKS)
_VECTOR_N = _norm_set(VECTOR_DATABASES)
_EMBED_N = _norm_set(EMBEDDING_PROVIDERS)
_AGENT_TOOLS_N = _norm_set(AGENT_TOOLS)
_CLOUD_N = _norm_set(CLOUD_SDKS)
_BLOCKLIST_N = _norm_set(_DIAGRAM_BLOCKLIST)

# ---------------------------------------------------------------------------
# Display names for common components
# ---------------------------------------------------------------------------
DISPLAY_NAMES: dict[str, str] = {
    "openai": "OpenAI",
    "anthropic": "Anthropic",
    "cohere": "Cohere",
    "google-generativeai": "Google AI",
    "vertexai": "Vertex AI",
    "mistralai": "Mistral",
    "litellm": "LiteLLM",
    "ollama": "Ollama",
    "replicate": "Replicate",
    "together": "Together AI",
    "fireworks": "Fireworks AI",
    "fireworks-ai": "Fireworks AI",
    "groq": "Groq",
    "vllm": "vLLM",
    "transformers": "Hugging Face Transformers",
    "langchain": "LangChain",
    "langchain-community": "LangChain Community",
    "langchain-core": "LangChain Core",
    "langchain_core": "LangChain Core",
    "langgraph": "LangGraph",
    "crewai": "CrewAI",
    "llama-index": "LlamaIndex",
    "llama-index-core": "LlamaIndex Core",
    "llama_index_core": "LlamaIndex Core",
    "chromadb": "ChromaDB",
    "pinecone": "Pinecone",
    "weaviate": "Weaviate",
    "qdrant-client": "Qdrant",
    "qdrant_client": "Qdrant",
    "faiss-cpu": "FAISS",
    "faiss-gpu": "FAISS",
    "faiss": "FAISS",
    "pgvector": "pgvector",
}


def _sanitize_id(name: str) -> str:
    """Make a string safe for Mermaid node ids."""
    if name is None:
        return "unknown"
    safe = name.replace(".", "_").replace("-", "_").replace(" ", "_").replace("/", "_")
    return "".join(c if c.isalnum() or c == "_" else "_" for c in safe)


def _quote_label(label: str) -> str:
    """Escape label for Mermaid."""
    if label is None:
        label = ""
    escaped = label.replace('"', "&quot;")
    return f'"{escaped}"'


def _display_name(component: Component) -> str:
    """Return human-readable name for diagram."""
    name = (component.name or "").lower().replace("-", "_")
    for key, display in DISPLAY_NAMES.items():
        if key.lower().replace("-", "_") == name:
            base = display
            break
    else:
        base = component.name
    if component.version:
        return f"{base}@{component.version}"
    return base


def _norm(name: str) -> str:
    """Normalize for set membership (lowercase, hyphens to underscores)."""
    return (name or "").lower().replace("-", "_")


def _in_set(name_norm: str, s: frozenset) -> bool:
    """Check if normalized name is in set (handles both hyphen and underscore forms)."""
    return name_norm in s or any(name_norm == x.replace("-", "_") for x in s)


def _assign_layer(c: Component) -> Optional[str]:
    """Assign component to a layer. Returns layer name or None if not AI-relevant."""
    name = _norm(c.name or "")
    if name in _BLOCKLIST_N or any(name.startswith(bl) for bl in _BLOCKLIST_N if bl.endswith("_")):
        return None
    if c.properties.get("aitrace:mcp_server"):
        return "mcp"
    if c.type == ComponentType.MODEL:
        return "models"
    if _in_set(name, AGENT_FRAMEWORKS):
        return "agents"
    if _in_set(name, RAG_FRAMEWORKS):
        return "rag"
    if _in_set(name, LLM_PROVIDERS) or _in_set(name, LOCAL_ML):
        return "llm"
    if _in_set(name, VECTOR_DATABASES):
        return "vector_db"
    if _in_set(name, EMBEDDING_PROVIDERS) and not _in_set(name, LLM_PROVIDERS):
        return "embedding"
    if _in_set(name, AGENT_TOOLS):
        return "tools"
    if _in_set(name, CLOUD_SDKS) or "azure" in name or "boto" in name:
        return "cloud"
    # google-cloud, google-cloud-aiplatform → cloud; google-generativeai → llm (already checked)
    if "google" in name and "generativeai" not in name and "vertex" not in name:
        return "cloud"
    return None


def to_ai_component_mermaid(
    aibom: AIBOM,
    architecture_result: Optional["ArchitectureResult"] = None,
) -> str:
    """
    Generate a left-to-right color-coded Mermaid flowchart for AI architecture.

    Layers flow left → right: Agents → LLM Providers → External APIs
                                     ↘ RAG → Vector DB ← Embeddings
                                     ↘ MCP Servers

    Color coding:
      purple  — Agent frameworks
      blue    — LLM providers
      teal    — RAG pipeline
      green   — Vector databases
      lime    — Embedding models
      orange  — MCP servers
      indigo  — External APIs / cloud
    """
    # Theme directive + layout
    lines: list[str] = [
        "%%{init: {'theme': 'dark', 'themeVariables': {"
        "'edgeLabelBackground': '#1e293b', "
        "'lineColor': '#475569', "
        "'fontSize': '13px'"
        "}}}%%",
        "flowchart LR",
        # ── Category class definitions ─────────────────────────────────────
        "    classDef agentCls  fill:#2d1b69,stroke:#7c3aed,color:#c4b5fd,rx:6",
        "    classDef llmCls    fill:#1e3a5f,stroke:#3b82f6,color:#93c5fd,rx:6",
        "    classDef ragCls    fill:#064e3b,stroke:#10b981,color:#6ee7b7,rx:6",
        "    classDef vecCls    fill:#065f46,stroke:#059669,color:#a7f3d0,rx:6",
        "    classDef embCls    fill:#1a2e1a,stroke:#4ade80,color:#86efac,rx:6",
        "    classDef mcpCls    fill:#431407,stroke:#ea580c,color:#fdba74,rx:6",
        "    classDef extCls    fill:#1e1b4b,stroke:#818cf8,color:#a5b4fc,rx:6",
        "    classDef cloudCls  fill:#1e293b,stroke:#64748b,color:#94a3b8,rx:6",
        "    classDef modelCls  fill:#1e1a2e,stroke:#a855f7,color:#d8b4fe,rx:6",
    ]

    # Categorize components by layer
    by_layer: dict[str, list] = {
        "agents": [], "rag": [], "llm": [], "vector_db": [],
        "embedding": [], "tools": [], "cloud": [], "models": [], "mcp": [],
    }
    for c in aibom.components:
        if c.name is None:
            continue
        layer = _assign_layer(c)
        if layer and layer in by_layer:
            by_layer[layer].append(c)

    mcp_servers = getattr(aibom, "mcp_servers", []) or []

    def _dedupe_primary(comps: list, primary_keys: frozenset) -> list:
        """Prefer primary packages (e.g. langchain over langchain-community)."""
        seen: set[str] = set()
        result: list[Component] = []
        for c in comps:
            n = (c.name or "").lower().replace("-", "_")
            base = n.split("_")[0]
            if n in primary_keys or base in primary_keys:
                if base in seen:
                    continue
                seen.add(base)
                seen.add(n)
                result.append(c)
        for c in comps:
            n = (c.name or "").lower().replace("-", "_")
            base = n.split("_")[0]
            if base not in seen:
                seen.add(base)
                result.append(c)
        return result

    agents = _dedupe_primary(by_layer["agents"], AGENT_FRAMEWORKS)
    llm = _dedupe_primary(by_layer["llm"], LLM_PROVIDERS)
    rag = _dedupe_primary(by_layer["rag"], RAG_FRAMEWORKS)
    emb_only = [
        c for c in by_layer["embedding"]
        if c.name and c.name.lower().replace("-", "_")
        not in {x.replace("-", "_") for x in LLM_PROVIDERS}
    ]

    # ── 1. Agent / Orchestration layer ────────────────────────────────────
    if agents:
        lines.append("")
        lines.append('    subgraph AGENTS["Agent Frameworks"]')
        for c in agents:
            nid = _sanitize_id(c.name)
            label = _display_name(c)
            lines.append(f"        {nid}[{_quote_label(label)}]")
        lines.append("    end")

    # ── 2. LLM Providers ──────────────────────────────────────────────────
    if llm:
        lines.append("")
        lines.append('    subgraph LLM["LLM Providers"]')
        for c in llm:
            nid = _sanitize_id(c.name)
            label = _display_name(c)
            lines.append(f"        {nid}[{_quote_label(label)}]")
        lines.append("    end")

    # ── 3. RAG Pipeline ───────────────────────────────────────────────────
    if rag:
        lines.append("")
        lines.append('    subgraph RAG["RAG Pipeline"]')
        for c in rag:
            nid = _sanitize_id(c.name)
            label = _display_name(c)
            lines.append(f"        {nid}[{_quote_label(label)}]")
        lines.append("    end")

    # ── 4. Embedding Models ───────────────────────────────────────────────
    if emb_only:
        lines.append("")
        lines.append('    subgraph EMBED["Embedding Models"]')
        for c in emb_only:
            nid = _sanitize_id(c.name)
            label = _display_name(c)
            lines.append(f"        {nid}[{_quote_label(label)}]")
        lines.append("    end")

    # ── 5. Vector Databases ───────────────────────────────────────────────
    if by_layer["vector_db"]:
        lines.append("")
        lines.append('    subgraph VECTOR["Vector Databases"]')
        for c in by_layer["vector_db"]:
            nid = _sanitize_id(c.name)
            label = _display_name(c)
            lines.append(f"        {nid}[{_quote_label(label)}]")
        lines.append("    end")

    # ── 6. MCP Servers ────────────────────────────────────────────────────
    if mcp_servers or by_layer["mcp"]:
        lines.append("")
        lines.append('    subgraph MCP["MCP Servers"]')
        for c in by_layer["mcp"]:
            nid = _sanitize_id(c.name)
            label = _display_name(c)
            lines.append(f"        {nid}[{_quote_label(label)}]")
        for m in mcp_servers:
            mid = _sanitize_id(m.id)
            flag = " ⚠" if getattr(m, "suspicious_description", False) else ""
            label = f"MCP: {m.name}{flag}"
            lines.append(f"        {mid}[{_quote_label(label)}]")
        lines.append("    end")

    # ── 7. External APIs ──────────────────────────────────────────────────
    api_map = {
        "openai": "OpenAI API",
        "anthropic": "Anthropic API",
        "cohere": "Cohere API",
        "google_generativeai": "Google AI API",
        "vertexai": "Vertex AI",
        "mistralai": "Mistral API",
        "litellm": "LiteLLM (unified)",
        "replicate": "Replicate API",
        "together": "Together API",
        "fireworks": "Fireworks API",
        "fireworks_ai": "Fireworks API",
        "groq": "Groq API",
    }
    api_keys_norm = {k.replace("-", "_") for k in api_map}
    api_sdks_present = [
        c for c in llm
        if c.name and (c.name or "").lower().replace("-", "_") in api_keys_norm
    ]
    if api_sdks_present:
        lines.append("")
        lines.append('    subgraph EXT["External APIs"]')
        seen_apis: set[str] = set()
        for c in api_sdks_present:
            key = (c.name or "").lower().replace("-", "_")
            api_label = api_map.get(key) or f"{c.name} API"
            if api_label not in seen_apis:
                seen_apis.add(api_label)
                nid = _sanitize_id(api_label)
                lines.append(f"        {nid}[{_quote_label(api_label)}]")
        lines.append("    end")

    # ── 8. Cloud Services ─────────────────────────────────────────────────
    if by_layer["cloud"]:
        lines.append("")
        lines.append('    subgraph CLOUD["Cloud Services"]')
        for c in by_layer["cloud"]:
            nid = _sanitize_id(c.name)
            label = _display_name(c)
            lines.append(f"        {nid}[{_quote_label(label)}]")
        lines.append("    end")

    # ── 9. Model Artifacts ────────────────────────────────────────────────
    if aibom.models:
        lines.append("")
        lines.append('    subgraph MODELS["Model Artifacts"]')
        for m in aibom.models[:8]:
            mid = _sanitize_id(m.id)
            label = f"{m.name} ({m.format})" if m.format else m.name
            lines.append(f"        {mid}[{_quote_label(label)}]")
        lines.append("    end")

    # ── 10. Tools ─────────────────────────────────────────────────────────
    if by_layer["tools"]:
        lines.append("")
        lines.append('    subgraph TOOLS["Agent Tools"]')
        for c in by_layer["tools"]:
            nid = _sanitize_id(c.name)
            label = _display_name(c)
            lines.append(f"        {nid}[{_quote_label(label)}]")
        lines.append("    end")

    # ── Edges ──────────────────────────────────────────────────────────────
    lines.append("")

    # Agents → LLM Providers
    if agents and llm:
        for a in agents[:4]:
            aid = _sanitize_id(a.name)
            for lc in llm[:3]:
                lid = _sanitize_id(lc.name)
                lines.append(f"    {aid} --> {lid}")

    # Agents → RAG
    if agents and rag:
        for a in agents[:2]:
            aid = _sanitize_id(a.name)
            for r in rag[:2]:
                rid = _sanitize_id(r.name)
                lines.append(f"    {aid} --> {rid}")

    # Agents → Tools
    if agents and by_layer["tools"]:
        for a in agents[:2]:
            aid = _sanitize_id(a.name)
            for t in by_layer["tools"][:3]:
                tid = _sanitize_id(t.name)
                lines.append(f"    {aid} --> {tid}")

    # RAG + Embeddings → Vector DBs
    vec_ids = [_sanitize_id(c.name) for c in by_layer["vector_db"]]
    for c in (rag + emb_only):
        if not c.name:
            continue
        nid = _sanitize_id(c.name)
        for vid in vec_ids[:3]:
            lines.append(f"    {nid} -.->|stores| {vid}")

    # Agents → MCP Servers (dashed = config relationship)
    if agents and (mcp_servers or by_layer["mcp"]):
        for a in agents[:3]:
            aid = _sanitize_id(a.name)
            for m in mcp_servers[:3]:
                mid = _sanitize_id(m.id)
                lines.append(f"    {aid} -.->|uses| {mid}")
        for a in agents[:2]:
            aid = _sanitize_id(a.name)
            for c in by_layer["mcp"][:2]:
                mid = _sanitize_id(c.name)
                lines.append(f"    {aid} -.->|uses| {mid}")

    # LLM Providers → External APIs
    for c in api_sdks_present:
        key = (c.name or "").lower().replace("-", "_")
        api_label = api_map.get(key, f"{c.name} API")
        api_nid = _sanitize_id(api_label)
        nid = _sanitize_id(c.name)
        lines.append(f"    {nid} -->|calls| {api_nid}")

    # Local ML → Model Artifacts
    local_ml_comps = [
        c for c in llm
        if c.name and c.name.lower().replace("-", "_") in {x.replace("-", "_") for x in LOCAL_ML}
    ]
    for c in local_ml_comps:
        nid = _sanitize_id(c.name)
        for m in aibom.models[:5]:
            mid = _sanitize_id(m.id)
            lines.append(f"    {nid} -.->|loads| {mid}")

    # Cloud → LLM (managed inference)
    if by_layer["cloud"] and llm:
        for c in by_layer["cloud"][:2]:
            cid = _sanitize_id(c.name)
            for lc in llm[:2]:
                lid = _sanitize_id(lc.name)
                lines.append(f"    {cid} -.->|provides| {lid}")

    # ── Class assignments ──────────────────────────────────────────────────
    lines.append("")
    if agents:
        ids = ",".join(_sanitize_id(c.name) for c in agents)
        lines.append(f"    class {ids} agentCls")
    if llm:
        ids = ",".join(_sanitize_id(c.name) for c in llm)
        lines.append(f"    class {ids} llmCls")
    if rag:
        ids = ",".join(_sanitize_id(c.name) for c in rag)
        lines.append(f"    class {ids} ragCls")
    if by_layer["vector_db"]:
        ids = ",".join(_sanitize_id(c.name) for c in by_layer["vector_db"])
        lines.append(f"    class {ids} vecCls")
    if emb_only:
        ids = ",".join(_sanitize_id(c.name) for c in emb_only)
        lines.append(f"    class {ids} embCls")
    all_mcp_ids = [_sanitize_id(c.name) for c in by_layer["mcp"]] + [_sanitize_id(m.id) for m in mcp_servers]
    if all_mcp_ids:
        lines.append(f"    class {','.join(all_mcp_ids)} mcpCls")
    if api_sdks_present:
        seen_api_labels: set[str] = set()
        ext_ids = []
        for c in api_sdks_present:
            key = (c.name or "").lower().replace("-", "_")
            api_label = api_map.get(key, f"{c.name} API")
            if api_label not in seen_api_labels:
                seen_api_labels.add(api_label)
                ext_ids.append(_sanitize_id(api_label))
        if ext_ids:
            lines.append(f"    class {','.join(ext_ids)} extCls")
    if by_layer["cloud"]:
        ids = ",".join(_sanitize_id(c.name) for c in by_layer["cloud"])
        lines.append(f"    class {ids} cloudCls")
    if aibom.models:
        ids = ",".join(_sanitize_id(m.id) for m in aibom.models[:8])
        lines.append(f"    class {ids} modelCls")

    return "\n".join(lines)
