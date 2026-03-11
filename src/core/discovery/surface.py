from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

from ..models import Component, ComponentType, Evidence, Finding, FindingCategory, Severity


AI_PACKAGES: Dict[str, str] = {
    # Python AI/LLM libraries
    "openai": "OpenAI",
    "anthropic": "Anthropic",
    "cohere": "Cohere",
    "google-generativeai": "Google Generative AI",
    "vertexai": "Google Vertex AI",
    "mistralai": "Mistral AI",
    "transformers": "Hugging Face Transformers",
    "accelerate": "Hugging Face Accelerate",
    "diffusers": "Hugging Face Diffusers",
    "langchain": "LangChain",
    "langchain-community": "LangChain Community",
    "llama-index": "LlamaIndex",
    "vllm": "vLLM",
    "litellm": "LiteLLM",
    # Dev tools
    "copilot": "GitHub Copilot",
}

AGENT_PACKAGES: Dict[str, str] = {
    "langgraph": "LangGraph",
    "crewai": "CrewAI",
    "autogen": "AutoGen",
    "semantic-kernel": "Microsoft Semantic Kernel",
    "semantic_kernel": "Microsoft Semantic Kernel",
    "haystack": "Haystack",
    "agentpy": "AgentPy",
    "agixt": "AGiXT",
}

MCP_PACKAGES: Dict[str, str] = {
    "mcp": "MCP Python SDK",
    "modelcontextprotocol": "Model Context Protocol",
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

    return components


def _scan_python_imports(root: Path) -> Set[str]:
    imported: Set[str] = set()
    for path in root.rglob("*.py"):
        try:
            source = path.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(source, filename=str(path))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported.add(alias.name.split(".")[0].lower())
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0].lower())
    return imported


def _build_findings_for_components(
    components: List[Component],
    imported_modules: Set[str],
    repo_root: Path,
) -> List[Finding]:
    findings: List[Finding] = []
    id_counter = 1

    def next_id() -> str:
        nonlocal id_counter
        val = f"SURF-{id_counter:04d}"
        id_counter += 1
        return val

    # Map by name
    comp_by_name: Dict[str, Component] = {c.name.lower(): c for c in components}

    # AI, agent, MCP, and cloud components from manifests
    for pkg, label in {**AI_PACKAGES, **AGENT_PACKAGES, **MCP_PACKAGES, **CLOUD_PACKAGES}.items():
        comp = comp_by_name.get(pkg)
        if not comp:
            continue
        is_ai = pkg in AI_PACKAGES
        is_agent = pkg in AGENT_PACKAGES
        is_mcp = pkg in MCP_PACKAGES
        if is_agent:
            category_tag = "ai-agent"
        elif is_mcp:
            category_tag = "mcp"
        elif is_ai:
            category_tag = "ai-library"
        else:
            category_tag = "cloud-provider"

        findings.append(
            Finding(
                id=next_id(),
                title=f"{label} dependency discovered",
                category=FindingCategory.SURFACE,
                severity=Severity.MEDIUM if is_ai else Severity.LOW,
                description=f"Package '{pkg}' appears in project manifests.",
                component_id=comp.id,
                evidence=[Evidence(description="Detected in manifest", file=str(repo_root))],
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
        if module in AI_PACKAGES or module in AGENT_PACKAGES or module in MCP_PACKAGES or module in CLOUD_PACKAGES:
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
    - Parse dependency manifests.
    - Scan imports for AI and cloud SDKs.
    """
    repo_root = repo_root.resolve()
    components = _scan_manifests(repo_root)
    imported_modules = _scan_python_imports(repo_root)
    comp_by_name: Dict[str, Component] = {c.name.lower(): c for c in components}

    # Add inferred components for AI/agent/MCP/cloud packages imported but not in manifests
    all_known = {**AI_PACKAGES, **AGENT_PACKAGES, **MCP_PACKAGES, **CLOUD_PACKAGES}
    for module in imported_modules:
        if module in all_known and module not in comp_by_name:
            pkg_id = f"pkg:pypi/{module}"  # inferred PyPI, no version
            inferred = Component(
                id=pkg_id,
                name=module,
                type=ComponentType.LIBRARY,
                version=None,
                purl=pkg_id,
                properties={"aitrace:inferred": "import-analysis"},
            )
            components.append(inferred)
            comp_by_name[module] = inferred

    findings = _build_findings_for_components(components, imported_modules, repo_root)
    return SurfaceDiscoveryResult(components=components, findings=findings)

