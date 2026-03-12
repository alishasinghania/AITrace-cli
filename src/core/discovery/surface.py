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

MCP_PACKAGES: Dict[str, str] = {
    "mcp": "MCP Python SDK",
    "modelcontextprotocol": "Model Context Protocol",
}

# Packages commonly used as agent tools (web search, browser automation, git, etc.)
AGENT_TOOL_PACKAGES: Dict[str, str] = {
    "duckduckgo-search": "DuckDuckGo Search",
    "duckduckgo_search": "DuckDuckGo Search",
    "playwright": "Playwright",
    "gitpython": "GitPython",
    "selenium": "Selenium",
}

CLOUD_PACKAGES: Dict[str, str] = {
    "boto3": "AWS",
    "google-cloud": "GCP",
    "azure-ai": "Azure",
    "azure-core": "Azure",
    "azure-identity": "Azure",
}


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
        data = tomllib.loads(content.encode("utf-8"))
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
    if first in AI_PACKAGES or first in AGENT_PACKAGES or first in MCP_PACKAGES or first in CLOUD_PACKAGES:
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
    all_known = {**AI_PACKAGES, **AGENT_PACKAGES, **MCP_PACKAGES, **CLOUD_PACKAGES, **AGENT_TOOL_PACKAGES}
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

    # AI, agent, MCP, cloud, and agent tool components from manifests/imports/config
    for pkg, label in {**AI_PACKAGES, **AGENT_PACKAGES, **MCP_PACKAGES, **CLOUD_PACKAGES, **AGENT_TOOL_PACKAGES}.items():
        comp = comp_by_name.get(pkg)
        if not comp:
            continue
        is_ai = pkg in AI_PACKAGES
        is_agent = pkg in AGENT_PACKAGES
        is_agent_tool = pkg in AGENT_TOOL_PACKAGES
        is_mcp = pkg in MCP_PACKAGES
        if is_agent:
            category_tag = "ai-agent"
        elif is_agent_tool:
            category_tag = "agent-tool"
        elif is_mcp:
            category_tag = "mcp"
        elif is_ai:
            category_tag = "ai-library"
        else:
            category_tag = "cloud-provider"

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

        findings.append(
            Finding(
                id=next_id(),
                title=f"{label} dependency discovered",
                category=FindingCategory.SURFACE,
                severity=Severity.MEDIUM if is_ai else Severity.LOW,
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
        if module in AI_PACKAGES or module in AGENT_PACKAGES or module in MCP_PACKAGES or module in CLOUD_PACKAGES or module in AGENT_TOOL_PACKAGES:
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
    all_known = {**AI_PACKAGES, **AGENT_PACKAGES, **MCP_PACKAGES, **CLOUD_PACKAGES, **AGENT_TOOL_PACKAGES}
    for module in imported_modules:
        if module in all_known and module not in comp_by_name:
            infer_source = "config-reference" if module in ref_providers else "import-analysis"
            pkg_id = f"pkg:pypi/{module}"  # inferred PyPI, no version
            inferred = Component(
                id=pkg_id,
                name=module,
                type=ComponentType.LIBRARY,
                version=None,
                purl=pkg_id,
                properties={"aitrace:inferred": infer_source},
            )
            components.append(inferred)
            comp_by_name[module] = inferred

    findings = _build_findings_for_components(components, imported_modules, repo_root)
    return SurfaceDiscoveryResult(components=components, findings=findings)

