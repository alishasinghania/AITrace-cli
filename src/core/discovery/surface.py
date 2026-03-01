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
            comp = Component(
                id=f"pkg:npm/{name}@{version}" if version else f"pkg:npm/{name}",
                name=name,
                type=ComponentType.LIBRARY,
                version=version,
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

    # AI and cloud components from manifests
    for pkg, label in {**AI_PACKAGES, **CLOUD_PACKAGES}.items():
        comp = comp_by_name.get(pkg)
        if not comp:
            continue
        is_ai = pkg in AI_PACKAGES
        category_tag = "ai-library" if is_ai else "cloud-provider"

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

    # Imports without explicit manifest entries (heuristic)
    for module in imported_modules:
        if module in AI_PACKAGES or module in CLOUD_PACKAGES:
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
    findings = _build_findings_for_components(components, imported_modules, repo_root)
    return SurfaceDiscoveryResult(components=components, findings=findings)

