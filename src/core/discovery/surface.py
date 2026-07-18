from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

from ..config import get_ignore_paths
from ..detectors.config_reference_detector import detect_config_references
from ..models import Component, ComponentType, Evidence, Finding, FindingCategory, Severity


AI_PACKAGES: Dict[str, str] = {
    # Python AI/LLM libraries
    "openai": "OpenAI",
    "anthropic": "Anthropic",
    "cohere": "Cohere",
    "google-generativeai": "Google Generative AI",
    "google": "Google AI (generic)",
    "vertexai": "Google Vertex AI",
    "mistralai": "Mistral AI",
    "transformers": "Hugging Face Transformers",
    "accelerate": "Hugging Face Accelerate",
    "diffusers": "Hugging Face Diffusers",
    "langchain": "LangChain",
    "langchain-community": "LangChain Community",
    "llama-index": "LlamaIndex",
    "llama-index-core": "LlamaIndex Core",
    "llama_index_core": "LlamaIndex Core",
    "gpt-index": "LlamaIndex (legacy)",
    "gpt_index": "LlamaIndex (legacy)",
    "ragas": "RAGAS",
    "ragstack": "RAGStack",
    "vllm": "vLLM",
    "litellm": "LiteLLM",
    "replicate": "Replicate",
    "together": "Together AI",
    "fireworks": "Fireworks AI",
    "fireworks-ai": "Fireworks AI",
    "groq": "Groq",
    "perplexity": "Perplexity",
    "ollama": "Ollama",
    "ai21": "AI21 Labs",
    "aleph-alpha-client": "Aleph Alpha",
    "aleph_alpha": "Aleph Alpha",
    # Dev tools
    "copilot": "GitHub Copilot",
}

AGENT_PACKAGES: Dict[str, str] = {
    # LangChain ecosystem (most common agent framework)
    "langchain": "LangChain",
    "langchain-community": "LangChain Community",
    "langchain-core": "LangChain Core",
    "langchain_core": "LangChain Core",  # import name for langchain-core pkg
    "langgraph": "LangGraph",
    "crewai": "CrewAI",
    "autogen": "AutoGen",
    "semantic-kernel": "Microsoft Semantic Kernel",
    "semantic_kernel": "Microsoft Semantic Kernel",
    "haystack": "Haystack",
    "haystack-ai": "Haystack AI",
    "haystack_ai": "Haystack AI",
    "agentpy": "AgentPy",
    "agixt": "AGiXT",
    "smolagents": "SmolAgents",
    "marvin": "Marvin",
    "superagi": "SuperAGI",
    "babyagi": "BabyAGI",
}

# Expanded from 2 entries — covers full MCP ecosystem
MCP_PACKAGES: Dict[str, str] = {
    "mcp": "MCP Python SDK",
    "modelcontextprotocol": "Model Context Protocol",
    "fastmcp": "FastMCP",
    "mcp-server-filesystem": "MCP Filesystem Server",
    "mcp-server-github": "MCP GitHub Server",
    "mcp-server-postgres": "MCP Postgres Server",
    "mcp-server-sqlite": "MCP SQLite Server",
    "anthropic-mcp": "Anthropic MCP",
}

# Packages commonly used as agent tools — expanded from 5 entries
AGENT_TOOL_PACKAGES: Dict[str, str] = {
    "duckduckgo-search": "DuckDuckGo Search",
    "duckduckgo_search": "DuckDuckGo Search",
    "playwright": "Playwright",
    "gitpython": "GitPython",
    "selenium": "Selenium",
    "tavily-python": "Tavily Search",
    "serpapi": "SerpAPI",
    "e2b": "E2B Code Interpreter",
    "composio": "Composio",
    "browserbase": "Browserbase",
    "firecrawl-py": "Firecrawl",
    "apify-client": "Apify",
}

CLOUD_PACKAGES: Dict[str, str] = {
    "boto3": "AWS",
    "google-cloud": "GCP",
    "azure-ai": "Azure",
    "azure-core": "Azure",
    "azure-identity": "Azure",
}

# ---------------------------------------------------------------------------
# Category dicts — each represents a distinct AI capability category.
# Keep separate so downstream code can classify components by category.
# All are merged into ALL_AI_PACKAGES for lookup.
# ---------------------------------------------------------------------------

VECTOR_STORE_PACKAGES: Dict[str, str] = {
    # Production vector databases
    "chromadb": "ChromaDB",
    "pinecone-client": "Pinecone",
    "pinecone": "Pinecone",
    "weaviate-client": "Weaviate",
    "weaviate": "Weaviate",
    "qdrant-client": "Qdrant",
    "qdrant": "Qdrant",
    "pymilvus": "Milvus",
    "milvus": "Milvus",
    "faiss-cpu": "FAISS",
    "faiss-gpu": "FAISS",
    "faiss": "FAISS",
    "opensearch-py": "OpenSearch",
    "pgvector": "pgvector",
    "lancedb": "LanceDB",
    "marqo": "Marqo",
    "turbopuffer": "Turbopuffer",
    "elasticsearch": "Elasticsearch (vector)",
    "redis": "Redis (vector)",
}

EMBEDDING_PACKAGES: Dict[str, str] = {
    "sentence-transformers": "Sentence Transformers",
    "tiktoken": "OpenAI Tokenizer",
    "voyageai": "Voyage AI",
    "nomic": "Nomic Embed",
    "fastembed": "FastEmbed",
    "cohere-embeddings": "Cohere Embeddings",
}

GUARDRAIL_PACKAGES: Dict[str, str] = {
    "guardrails-ai": "Guardrails AI",
    "nemoguardrails": "NeMo Guardrails",
    "llm-guard": "LLM Guard",
    "rebuff": "Rebuff",
    "presidio-analyzer": "Microsoft Presidio",
    "detoxify": "Detoxify",
    "langkit": "LangKit",
}

OBSERVABILITY_PACKAGES: Dict[str, str] = {
    "langfuse": "Langfuse",
    "langsmith": "LangSmith",
    "arize-ai": "Arize AI",
    "whylogs": "WhyLogs",
    "phoenix": "Arize Phoenix",
    "helicone": "Helicone",
    "trulens-eval": "TruLens",
    "deepeval": "DeepEval",
}

NEW_AGENT_PACKAGES: Dict[str, str] = {
    # New 2024-2025 agent frameworks not in AGENT_PACKAGES yet
    "pydantic-ai": "Pydantic AI",
    "pydantic_ai": "Pydantic AI",
    "agno": "Agno",
    "dspy-ai": "DSPy",
    "dspy": "DSPy",
    "instructor": "Instructor",
    "guidance": "Guidance",
    "phidata": "Phidata",
    "phi": "Phidata",
    "openai-agents": "OpenAI Agents SDK",
    "google-adk": "Google ADK",
    "letta": "Letta (MemGPT)",
    "memgpt": "MemGPT",
    "controlflow": "ControlFlow",
}

# ---------------------------------------------------------------------------
# Consolidated lookup — single dict for scanning, preserves category separation.
# Future: add new category dict above and merge it here.
# ---------------------------------------------------------------------------
ALL_AI_PACKAGES: Dict[str, str] = {
    **AI_PACKAGES,
    **AGENT_PACKAGES,
    **MCP_PACKAGES,
    **AGENT_TOOL_PACKAGES,
    **CLOUD_PACKAGES,
    **VECTOR_STORE_PACKAGES,
    **EMBEDDING_PACKAGES,
    **GUARDRAIL_PACKAGES,
    **OBSERVABILITY_PACKAGES,
    **NEW_AGENT_PACKAGES,
}


def get_package_category(package_name: str) -> str:
    """
    Return the category string for a given package name.

    Used by downstream code (exporters, risk scoring) to classify
    components without reimplementing the registry lookup.

    Returns one of: vector_store | embedding | guardrail | observability |
    agent_framework | mcp | llm_sdk | cloud | agent_tool | unknown
    """
    norm = package_name.lower().replace("-", "_").replace(" ", "_")

    _registry: List[Tuple[Dict[str, str], str]] = [
        (VECTOR_STORE_PACKAGES, "vector_store"),
        (EMBEDDING_PACKAGES, "embedding"),
        (GUARDRAIL_PACKAGES, "guardrail"),
        (OBSERVABILITY_PACKAGES, "observability"),
        (NEW_AGENT_PACKAGES, "agent_framework"),
        (MCP_PACKAGES, "mcp"),
        (AGENT_PACKAGES, "agent_framework"),
        (AGENT_TOOL_PACKAGES, "agent_tool"),
        (AI_PACKAGES, "llm_sdk"),
        (CLOUD_PACKAGES, "cloud"),
    ]
    for pkg_dict, category in _registry:
        for key in pkg_dict:
            if key.lower().replace("-", "_") == norm:
                return category
    return "unknown"


@dataclass
class SurfaceDiscoveryResult:
    components: List[Component]
    findings: List[Finding]


def _read_lines(path: Path) -> List[str]:
    try:
        return path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return []


REQ_LINE_RE = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9_.\-]+)" r"(?:\[(?P<extras>[^\]]+)\])?" r"\s*(?P<specifier>==|>=|<=|~=|>|<)?\s*(?P<version>[^\s;]+)?"
)


def _parse_requirements(path: Path) -> Iterable[Tuple[str, Optional[str]]]:
    for line in _read_lines(path):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = REQ_LINE_RE.match(line)
        if not m:
            continue
        name = m.group("name").lower()
        version = m.group("version")
        yield name, version


def _parse_package_json(path: Path) -> Dict[str, str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    deps: Dict[str, str] = {}
    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        for name, version in data.get(section, {}).items():
            deps[name.lower()] = version
    return deps


def _parse_pyproject(path: Path) -> Iterable[Tuple[str, Optional[str]]]:
    """Extract [project] dependencies from pyproject.toml. Uses tomllib (3.11+) or regex fallback."""
    if not path.exists():
        return
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return
    # Try tomllib (Python 3.11+) - requires bytes
    try:
        import tomllib
        data = tomllib.loads(content)
    except ImportError:
        data = None
    if data:
        project = data.get("project", {})
        deps = project.get("dependencies", [])
        for dep in deps:
            if isinstance(dep, str):
                name = dep.split("[")[0].split(">=")[0].split("==")[0].split("<")[0].strip()
                if name and not name.startswith("$"):
                    yield name.lower(), None
        # [project.optional-dependencies] - dev, test, ml, etc.
        opt_deps = project.get("optional-dependencies", {})
        if isinstance(opt_deps, dict):
            for group_deps in opt_deps.values():
                if isinstance(group_deps, list):
                    for dep in group_deps:
                        if isinstance(dep, str):
                            name = dep.split("[")[0].split(">=")[0].split("==")[0].split("<")[0].strip()
                            if name and not name.startswith("$"):
                                yield name.lower(), None
        return
    # Regex fallback for Python < 3.11
    deps_match = re.search(
        r"\[project\].*?dependencies\s*=\s*\[(.*?)\](?:\s*(?:\n\[|\Z))",
        content,
        re.DOTALL,
    )
    if deps_match:
        for m in re.finditer(r'"([^"]+)"', deps_match.group(1)):
            pkg = m.group(1).split("[")[0].split(">=")[0].split("==")[0].strip()
            if pkg and not pkg.startswith("$"):
                yield pkg.lower(), None
    # [project.optional-dependencies] or [project.optional-dependencies.<group>]
    opt_match = re.search(
        r"\[project\.optional-dependencies(?:\.[^\]]+)?\].*?=\s*\[(.*?)\](?:\s*(?:\n\[|\Z))",
        content,
        re.DOTALL,
    )
    if opt_match:
        for m in re.finditer(r'"([^"]+)"', opt_match.group(1)):
            pkg = m.group(1).split("[")[0].split(">=")[0].split("==")[0].strip()
            if pkg and not pkg.startswith("$"):
                yield pkg.lower(), None


# Import module -> package key (for packages where import name differs from PyPI name)
_IMPORT_TO_AGENT_TOOL: Dict[str, str] = {
    "git": "gitpython",  # GitPython provides 'git' module
}


def _normalize_import_to_ai_package(module: str) -> Optional[str]:
    """Map import path to AI_PACKAGES key. Handles google.generativeai, google.genai, etc."""
    parts = module.lower().split(".")
    if not parts:
        return None
    first = parts[0]
    if len(parts) >= 2 and first == "google":
        if "generativeai" in parts or "genai" in parts:
            return "google-generativeai"
        if "cloud" in parts and "aiplatform" in parts:
            return "vertexai"
    if first in ALL_AI_PACKAGES:
        return first
    if first in _IMPORT_TO_AGENT_TOOL:
        return _IMPORT_TO_AGENT_TOOL[first]
    if first in AGENT_TOOL_PACKAGES:
        return first
    return None


def _scan_manifests(root: Path) -> List[Component]:
    components: List[Component] = []

    req_file = root / "requirements.txt"
    if req_file.exists():
        for name, version in _parse_requirements(req_file):
            comp = Component(
                id=f"pkg:pypi/{name}@{version}" if version else f"pkg:pypi/{name}",
                name=name,
                type=ComponentType.LIBRARY,
                version=version,
            )
            components.append(comp)

    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        seen_pyproject: Set[str] = set()
        for name, version in _parse_pyproject(pyproject):
            if name and name not in seen_pyproject:
                seen_pyproject.add(name)
                comp = Component(
                    id=f"pkg:pypi/{name}@{version}" if version else f"pkg:pypi/{name}",
                    name=name,
                    type=ComponentType.LIBRARY,
                    version=version,
                )
                components.append(comp)

    pkg_json = root / "package.json"
    if pkg_json.exists():
        for name, version in _parse_package_json(pkg_json).items():
            props = {}
            if "@modelcontextprotocol" in name.lower() or "mcp-server" in name.lower():
                props["aitrace:mcp_server"] = True
            comp = Component(
                id=f"pkg:npm/{name}@{version}" if version else f"pkg:npm/{name}",
                name=name,
                type=ComponentType.LIBRARY,
                version=version,
                properties=props,
            )
            components.append(comp)

    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        seen_pyproject = set()
        for name, version in _parse_pyproject(pyproject):
            if name and name not in seen_pyproject:
                seen_pyproject.add(name)
                components.append(Component(
                    id=f"pkg:pypi/{name}@{version}" if version else f"pkg:pypi/{name}",
                    name=name,
                    type=ComponentType.LIBRARY,
                    version=version,
                ))

    return components


def _extract_str_arg(node: ast.AST) -> Optional[str]:
    """Extract string from ast.Constant or ast.Str (for dynamic import args)."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if hasattr(ast, "Str") and isinstance(node, ast.Str):  # Python 3.7
        return node.s
    return None


def _scan_python_imports(root: Path) -> Set[str]:
    from ..detectors._ast_utils import should_skip_path

    imported: Set[str] = set()
    all_known = ALL_AI_PACKAGES
    for path in root.rglob("*.py"):
        if should_skip_path(path, root):
            continue
        try:
            source = path.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(source, filename=str(path))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    mod = alias.name.split(".")[0].lower()
                    normalized = _normalize_import_to_ai_package(alias.name)
                    if normalized:
                        imported.add(normalized)
                    elif mod in all_known:
                        imported.add(mod)
            elif isinstance(node, ast.ImportFrom) and node.module:
                mod = node.module.split(".")[0].lower()
                normalized = _normalize_import_to_ai_package(node.module)
                if normalized:
                    imported.add(normalized)
                elif mod in all_known:
                    imported.add(mod)
            elif isinstance(node, ast.Call):
                # Dynamic imports: __import__("openai"), importlib.import_module("anthropic")
                is_dynamic_import = False
                if isinstance(node.func, ast.Name) and node.func.id == "__import__":
                    is_dynamic_import = True
                elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                    if node.func.value.id == "importlib" and node.func.attr == "import_module":
                        is_dynamic_import = True
                if not is_dynamic_import or not node.args:
                    continue
                mod_str = _extract_str_arg(node.args[0])
                if not mod_str:
                    continue
                normalized = _normalize_import_to_ai_package(mod_str)
                if normalized:
                    imported.add(normalized)
                else:
                    first = mod_str.split(".")[0].lower()
                    if first in all_known:
                        imported.add(first)
    return imported


def _build_findings_for_components(
    components: List[Component],
    imported_modules: Set[str],
    repo_root: Path,
    config_ref_providers: Optional[Set[str]] = None,
) -> List[Finding]:
    findings: List[Finding] = []
    id_counter = 1

    def next_id() -> str:
        nonlocal id_counter
        val = f"SURF-{id_counter:04d}"
        id_counter += 1
        return val

    # Map by name (and normalized form for packages like duckduckgo-search/duckduckgo_search)
    comp_by_name: Dict[str, Component] = {}
    for c in components:
        k = (c.name or "").lower()
        comp_by_name[k] = c
        comp_by_name[k.replace("-", "_")] = c

    # AI-category tag map — used for finding tags
    _cat_tag_map = {
        "agent_framework": "ai-agent",
        "agent_tool": "agent-tool",
        "mcp": "mcp",
        "llm_sdk": "ai-library",
        "cloud": "cloud-provider",
        "vector_store": "vector-store",
        "embedding": "embedding",
        "guardrail": "guardrail",
        "observability": "observability",
    }

    # AI, agent, MCP, cloud, and agent tool components from manifests/imports/config
    for pkg, label in ALL_AI_PACKAGES.items():
        comp = comp_by_name.get(pkg)
        if not comp:
            continue
        ai_category = get_package_category(pkg)
        category_tag = _cat_tag_map.get(ai_category, "ai-library")
        # Annotate component with AI category for downstream use
        if ai_category != "unknown" and "ai_category" not in comp.properties:
            comp.properties["ai_category"] = ai_category

        inferred = comp.properties.get("aitrace:inferred")
        if inferred == "config-reference":
            desc = f"AI provider '{pkg}' referenced in config files, strings, or URLs."
            evidence_desc = "Config/string reference"
        elif inferred == "import-analysis":
            desc = f"Module '{pkg}' imported in source files but not in manifests."
            evidence_desc = "Static import analysis"
        else:
            desc = f"Package '{pkg}' appears in project manifests."
            evidence_desc = "Detected in manifest"

        # llm_sdk findings are MEDIUM (direct LLM exposure); everything else LOW
        sev = Severity.MEDIUM if ai_category == "llm_sdk" else Severity.LOW
        findings.append(
            Finding(
                id=next_id(),
                title=f"{label} dependency discovered",
                category=FindingCategory.SURFACE,
                severity=sev,
                description=desc,
                component_id=comp.id,
                evidence=[Evidence(description=evidence_desc, file=str(repo_root))],
                tags=[category_tag],
            )
        )

    # MCP server packages from npm (@modelcontextprotocol/server-*)
    for c in components:
        if c.properties.get("aitrace:mcp_server"):
            findings.append(
                Finding(
                    id=next_id(),
                    title=f"MCP server package: {c.name}",
                    category=FindingCategory.SURFACE,
                    severity=Severity.MEDIUM,
                    description=f"MCP server package '{c.name}' in package.json.",
                    component_id=c.id,
                    evidence=[Evidence(description="Detected in package.json", file=str(repo_root))],
                    tags=["mcp-server"],
                )
            )

    # Imports without explicit manifest entries (heuristic)
    for module in imported_modules:
        if module in ALL_AI_PACKAGES:
            if module not in comp_by_name:
                findings.append(
                    Finding(
                        id=next_id(),
                        title=f"{module} usage detected in code",
                        category=FindingCategory.SURFACE,
                        severity=Severity.LOW,
                        description=f"Module '{module}' is imported in source files but not found in manifests.",
                        component_id=None,
                        evidence=[Evidence(description="Static import analysis")],
                        tags=["import-only"],
                    )
                )

    return findings


def discover_surface(repo_root: Path) -> SurfaceDiscoveryResult:
    """
    Perform surface discovery:
    - Parse dependency manifests (requirements.txt, package.json, pyproject.toml).
    - Scan imports for AI and cloud SDKs.
    - Scan config/string references (API URLs, provider keys, model IDs).
    """
    repo_root = repo_root.resolve()
    components = _scan_manifests(repo_root)
    imported_modules = _scan_python_imports(repo_root)

    # Config/string reference detection (catches aibommaker-style metadata)
    from ..detectors.config_reference_detector import detect_config_references
    config_refs = detect_config_references(repo_root)
    ref_providers = {p for p, _ in config_refs}
    imported_modules = imported_modules | ref_providers

    comp_by_name: Dict[str, Component] = {}
    for c in components:
        k = (c.name or "").lower()
        comp_by_name[k] = c
        comp_by_name[k.replace("-", "_")] = c

    # Add inferred components for AI/agent/MCP/cloud/agent-tool packages imported or referenced but not in manifests
    for module in imported_modules:
        if module in ALL_AI_PACKAGES and module not in comp_by_name:
            infer_source = "config-reference" if module in ref_providers else "import-analysis"
            pkg_id = f"pkg:pypi/{module}"  # inferred PyPI, no version
            infer_props: Dict[str, Any] = {"aitrace:inferred": infer_source}
            ai_cat = get_package_category(module)
            if ai_cat != "unknown":
                infer_props["ai_category"] = ai_cat
            inferred = Component(
                id=pkg_id,
                name=module,
                type=ComponentType.LIBRARY,
                version=None,
                purl=pkg_id,
                properties=infer_props,
            )
            components.append(inferred)
            comp_by_name[module] = inferred

    findings = _build_findings_for_components(components, imported_modules, repo_root)
    return SurfaceDiscoveryResult(components=components, findings=findings)

