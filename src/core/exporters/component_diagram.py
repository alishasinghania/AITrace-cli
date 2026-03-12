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
    Generate a layered Mermaid flowchart for AI architecture.

    Layers: Application → Agents → LLM Providers | RAG Pipeline | Vector DBs | Tools | Model Artifacts | MCP
    """
    lines: list[str] = ["flowchart TB"]

    # Optional: inferred architecture banner
    if architecture_result and architecture_result.architecture_types != ["Unknown"]:
        arch_label = " + ".join(architecture_result.architecture_types)
        lines.append(f'    subgraph inferred["Inferred: {arch_label}"]')
        for c in architecture_result.components[:6]:
            nid = "inf_" + _sanitize_id(c)
            lines.append(f'        {nid}["{c}"]')
        lines.append("    end")

    # Categorize components by layer
    by_layer: dict[str, list] = {
        "agents": [],
        "rag": [],
        "llm": [],
        "vector_db": [],
        "embedding": [],
        "tools": [],
        "cloud": [],
        "models": [],
        "mcp": [],
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
        # First pass: primary keys only (one per logical component)
        for c in comps:
            n = (c.name or "").lower().replace("-", "_")
            base = n.split("_")[0].split("-")[0]
            if n in primary_keys or base in primary_keys:
                if base in seen:
                    continue
                seen.add(base)
                seen.add(n)
                result.append(c)
        # Second pass: add non-primary that aren't covered
        for c in comps:
            n = (c.name or "").lower().replace("-", "_")
            base = n.split("_")[0].split("-")[0]
            if base not in seen:
                seen.add(base)
                result.append(c)
        return result

    # --- 1. Application layer ---
    lines.append('    subgraph app["Application Layer"]')
    lines.append("        repo[Repository]")
    lines.append("    end")

    # --- 2. Agent / Orchestration layer ---
    agents = _dedupe_primary(by_layer["agents"], AGENT_FRAMEWORKS)
    if agents:
        lines.append("")
        lines.append('    subgraph agents["Agent / Orchestration"]')
        for c in agents:
            nid = _sanitize_id(c.name)
            label = _display_name(c)
            lines.append(f"        {nid}[{_quote_label(label)}]")
        lines.append("    end")

    # --- 3. LLM Providers ---
    llm = _dedupe_primary(by_layer["llm"], LLM_PROVIDERS)
    if llm:
        lines.append("")
        lines.append('    subgraph llm["LLM Providers"]')
        for c in llm:
            nid = _sanitize_id(c.name)
            label = _display_name(c)
            lines.append(f"        {nid}[{_quote_label(label)}]")
        lines.append("    end")

    # --- 4. RAG Pipeline ---
    rag = _dedupe_primary(by_layer["rag"], RAG_FRAMEWORKS)
    if rag:
        lines.append("")
        lines.append('    subgraph rag["RAG Pipeline"]')
        for c in rag:
            nid = _sanitize_id(c.name)
            label = _display_name(c)
            lines.append(f"        {nid}[{_quote_label(label)}]")
        lines.append("    end")

    # --- 5. Embedding Models (only if not already in LLM) ---
    emb_names = {c.name.lower().replace("-", "_") for c in by_layer["embedding"]}
    emb_only = [c for c in by_layer["embedding"] if c.name and c.name.lower().replace("-", "_") not in {x.replace("-", "_") for x in LLM_PROVIDERS}]
    if emb_only:
        lines.append("")
        lines.append('    subgraph embedding["Embedding Models"]')
        for c in emb_only:
            nid = _sanitize_id(c.name)
            label = _display_name(c)
            lines.append(f"        {nid}[{_quote_label(label)}]")
        lines.append("    end")

    # --- 6. Vector Databases ---
    if by_layer["vector_db"]:
        lines.append("")
        lines.append('    subgraph vector["Vector Databases"]')
        for c in by_layer["vector_db"]:
            nid = _sanitize_id(c.name)
            label = _display_name(c)
            lines.append(f"        {nid}[{_quote_label(label)}]")
        lines.append("    end")

    # --- 7. Tools ---
    if by_layer["tools"]:
        lines.append("")
        lines.append('    subgraph tools["External Tools"]')
        for c in by_layer["tools"]:
            nid = _sanitize_id(c.name)
            label = _display_name(c)
            lines.append(f"        {nid}[{_quote_label(label)}]")
        lines.append("    end")

    # --- 8. Model Artifacts ---
    if aibom.models:
        lines.append("")
        lines.append('    subgraph models["Model Artifacts"]')
        for m in aibom.models[:8]:
            mid = _sanitize_id(m.id)
            label = f"{m.name} ({m.format})" if m.format else m.name
            lines.append(f"        {mid}[{_quote_label(label)}]")
        lines.append("    end")

    # --- 9. MCP Servers ---
    if mcp_servers or by_layer["mcp"]:
        lines.append("")
        lines.append('    subgraph mcp["MCP Servers"]')
        for c in by_layer["mcp"]:
            nid = _sanitize_id(c.name)
            label = _display_name(c)
            lines.append(f"        {nid}[{_quote_label(label)}]")
        for m in mcp_servers:
            mid = _sanitize_id(m.id)
            label = f"MCP: {m.name}"
            lines.append(f"        {mid}[{_quote_label(label)}]")
        lines.append("    end")

    # --- 10. External APIs (implied from LLM SDKs) ---
    api_map = {
        "openai": "OpenAI API",
        "anthropic": "Anthropic API",
        "cohere": "Cohere API",
        "google_generativeai": "Google AI API",
        "vertexai": "Vertex AI",
        "mistralai": "Mistral API",
        "litellm": "Unified API",
        "replicate": "Replicate API",
        "together": "Together API",
        "fireworks": "Fireworks API",
        "fireworks_ai": "Fireworks API",
        "groq": "Groq API",
    }
    api_keys_norm = {k.replace("-", "_") for k in api_map}
    api_sdks_present = [c for c in llm if c.name and (c.name or "").lower().replace("-", "_") in api_keys_norm]
    if api_sdks_present:
        lines.append("")
        lines.append('    subgraph external["External APIs"]')
        seen_apis: set[str] = set()
        for c in api_sdks_present:
            key = (c.name or "").lower().replace("-", "_")
            api_label = api_map.get(key) or next((v for k, v in api_map.items() if k.replace("-", "_") == key), f"{c.name} API")
            if api_label not in seen_apis:
                seen_apis.add(api_label)
                nid = _sanitize_id(api_label)
                lines.append(f"        {nid}[{_quote_label(api_label)}]")
        lines.append("    end")

    # --- 11. Cloud Services ---
    if by_layer["cloud"]:
        lines.append("")
        lines.append('    subgraph cloud["Cloud Services"]')
        for c in by_layer["cloud"]:
            nid = _sanitize_id(c.name)
            label = _display_name(c)
            lines.append(f"        {nid}[{_quote_label(label)}]")
        lines.append("    end")

    # ---------------------------------------------------------------------------
    # Edges: map relationships between layers
    # ---------------------------------------------------------------------------
    all_ai_ids: set[str] = set()

    def _collect_ids(comps: list, extra: list = None) -> set[str]:
        ids = {_sanitize_id(c.name) for c in comps if c.name}
        if extra:
            for m in extra:
                ids.add(_sanitize_id(getattr(m, "id", None) or getattr(m, "name", "")))
        return ids

    for comps in by_layer.values():
        all_ai_ids |= _collect_ids(comps)
    all_ai_ids |= _collect_ids([], mcp_servers)
    all_ai_ids |= {_sanitize_id(m.id) for m in aibom.models}

    lines.append("")
    # Application → Agents, LLM, RAG, Tools, MCP, Cloud
    for layer_name, comps in by_layer.items():
        if not comps and layer_name != "models":
            continue
        if layer_name == "models":
            for m in aibom.models[:8]:
                mid = _sanitize_id(m.id)
                lines.append(f"    repo -.->|contains| {mid}")
        else:
            for c in comps:
                nid = _sanitize_id(c.name)
                lines.append(f"    repo --> {nid}")
    for m in mcp_servers:
        mid = _sanitize_id(m.id)
        lines.append(f"    repo -.->|config| {mid}")

    # Agents → LLM Providers
    if agents and llm:
        for a in agents[:3]:
            aid = _sanitize_id(a.name)
            for l in llm[:4]:
                lid = _sanitize_id(l.name)
                lines.append(f"    {aid} --> {lid}")

    # Agents → Tools
    if agents and by_layer["tools"]:
        for a in agents[:2]:
            aid = _sanitize_id(a.name)
            for t in by_layer["tools"][:3]:
                tid = _sanitize_id(t.name)
                lines.append(f"    {aid} --> {tid}")

    # Agents → RAG (when both present)
    if agents and rag:
        for a in agents[:2]:
            aid = _sanitize_id(a.name)
            for r in rag[:2]:
                rid = _sanitize_id(r.name)
                lines.append(f"    {aid} --> {rid}")

    # RAG / Embeddings → Vector DBs (orchestration and embedding writes, not LLM directly)
    vec_ids = {_sanitize_id(c.name) for c in by_layer["vector_db"]}
    rag_emb = rag + by_layer["embedding"]
    for c in rag_emb:
        if not c.name:
            continue
        nid = _sanitize_id(c.name)
        for vid in list(vec_ids)[:3]:
            lines.append(f"    {nid} -.->|writes| {vid}")

    # Agents → MCP Servers
    if (agents or rag) and (mcp_servers or by_layer["mcp"]):
        for a in agents[:2]:
            aid = _sanitize_id(a.name)
            for m in mcp_servers[:2]:
                mid = _sanitize_id(m.id)
                lines.append(f"    {aid} -.->|config| {mid}")
        for c in by_layer["mcp"][:2]:
            mid = _sanitize_id(c.name)
            if agents:
                aid = _sanitize_id(agents[0].name)
                lines.append(f"    {aid} -.->|config| {mid}")

    # LLM Providers → External APIs
    for c in api_sdks_present:
        key = (c.name or "").lower().replace("-", "_")
        api_label = api_map.get(key, f"{c.name} API")
        api_nid = _sanitize_id(api_label)
        nid = _sanitize_id(c.name)
        lines.append(f"    {nid} --> {api_nid}")

    # Local ML / LLM → Model Artifacts
    local_ml_comps = [c for c in llm if c.name and c.name.lower().replace("-", "_") in {x.replace("-", "_") for x in LOCAL_ML}]
    for c in local_ml_comps:
        nid = _sanitize_id(c.name)
        for m in aibom.models[:5]:
            mid = _sanitize_id(m.id)
            lines.append(f"    {nid} -.->|loads| {mid}")
    if aibom.models and not local_ml_comps:
        for m in aibom.models[:5]:
            mid = _sanitize_id(m.id)
            lines.append(f"    repo -.->|contains| {mid}")

    return "\n".join(lines)
