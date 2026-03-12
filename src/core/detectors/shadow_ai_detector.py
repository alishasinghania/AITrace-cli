"""
Shadow AI detector – AI API used in code but NOT declared in dependency manifests.

Shadow AI = ungoverned usage: openai/anthropic/cohere etc. appear in code
but the package is missing from requirements.txt, pyproject.toml, or setup.py.

Skips framework repositories (e.g. llama-index, langchain) that by design
integrate with multiple providers.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from .base import DetectionResult
from ._ast_utils import get_call_target_chain, scan_ast, walk_python_files

# Map: module name (in code) -> package names (in manifests, normalized)
AI_API_MODULE_TO_PACKAGES: Dict[str, Set[str]] = {
    "openai": {"openai"},
    "anthropic": {"anthropic"},
    "cohere": {"cohere"},
    "vertexai": {"vertexai", "google-cloud-aiplatform"},
    "generativeai": {"google-generativeai", "generativeai"},
    "genai": {"google-generativeai", "generativeai"},
    "mistral": {"mistralai", "mistral"},
    "litellm": {"litellm"},
    "replicate": {"replicate"},
    "together": {"together"},
    "fireworks": {"fireworks", "fireworks-ai"},
    "groq": {"groq"},
    "ai21": {"ai21"},
    "aleph_alpha": {"aleph-alpha-client"},
    "perplexity": {"perplexity"},
    "ollama": {"ollama"},
    # AWS Bedrock via boto3
    "bedrock": {"boto3"},
}

# Package names that indicate a framework repo (skip Shadow AI detection)
FRAMEWORK_PACKAGE_NAMES = frozenset({
    "llama-index", "llama_index", "llamaindex",
    "llama-index-core", "llama_index_core", "gpt-index", "gpt_index",
    "langchain", "langchain-core", "langchain-community",
    "langgraph", "langgraph-sdk",
    "haystack", "haystack-ai",
    "ragas", "ragstack",
    "semantic-kernel", "semantic_kernel",
    "crewai", "crewai-tools",
    "autogen", "litellm",  # litellm is a proxy/framework
    "smolagents", "marvin", "superagi", "babyagi",
})


def _get_declared_deps(repo_root: Path) -> Set[str]:
    """
    Extract declared Python dependencies from requirements.txt, pyproject.toml, setup.py.
    Returns normalized package names (lowercase, - replaced with _).
    """
    declared: Set[str] = set()
    repo_root = repo_root.resolve()

    def _norm(pkg: str) -> str:
        return pkg.lower().replace("-", "_").replace(" ", "_")

    # requirements.txt
    req_file = repo_root / "requirements.txt"
    if req_file.exists():
        try:
            for line in req_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip().split("#")[0].strip()
                if not line or line.startswith("-"):
                    continue
                m = re.match(r"^([a-zA-Z0-9_.\-]+)", line)
                if m:
                    declared.add(_norm(m.group(1)))
        except OSError:
            pass

    # pyproject.toml
    pyproject = repo_root / "pyproject.toml"
    if pyproject.exists():
        try:
            content = pyproject.read_text(encoding="utf-8", errors="ignore")
            # [project] dependencies = ["pkg>=1.0", ...]
            deps_match = re.search(
                r"\[project\].*?dependencies\s*=\s*\[(.*?)\](?:\s*(?:\n\[|\Z))",
                content,
                re.DOTALL,
            )
            if deps_match:
                for m in re.finditer(r'"([^"]+)"', deps_match.group(1)):
                    pkg = m.group(1).split("[")[0].split(">=")[0].split("==")[0].strip()
                    if pkg and not pkg.startswith("$"):
                        declared.add(_norm(pkg))
            # [project.optional-dependencies] *
            opt_match = re.search(
                r"\[project\.optional-dependencies(?:\.[^\]]+)?\].*?=\s*\[(.*?)\](?:\s*(?:\n\[|\Z))",
                content,
                re.DOTALL,
            )
            if opt_match:
                for m in re.finditer(r'"([^"]+)"', opt_match.group(1)):
                    pkg = m.group(1).split("[")[0].split(">=")[0].split("==")[0].strip()
                    if pkg and not pkg.startswith("$"):
                        declared.add(_norm(pkg))
            # [tool.poetry.dependencies]
            poetry_match = re.search(
                r"\[tool\.poetry\.dependencies\].*?(?:\n(\[[^\]]+\])|$)",
                content,
                re.DOTALL,
            )
            if poetry_match:
                for m in re.finditer(r'^(\w[\w\-]*)\s*=', poetry_match.group(0), re.MULTILINE):
                    pkg = m.group(1)
                    if pkg not in ("python", "version"):
                        declared.add(_norm(pkg))
        except OSError:
            pass

    # setup.py - install_requires and extras_require
    setup_py = repo_root / "setup.py"
    if setup_py.exists():
        try:
            content = setup_py.read_text(encoding="utf-8", errors="ignore")
            # install_requires = ["pkg", ...] or install_requires=["pkg",]
            for pat in (
                r"install_requires\s*=\s*\[(.*?)\]",
                r"extras_require\s*=\s*\{[^}]*(?:\[(.*?)\])",
            ):
                for m in re.finditer(pat, content, re.DOTALL):
                    for pkg in re.findall(r'["\']([a-zA-Z0-9_.\-]+)["\']', m.group(1)):
                        if not pkg.startswith("$"):
                            declared.add(_norm(pkg))
        except OSError:
            pass

    return declared


def _get_project_name(repo_root: Path) -> Optional[str]:
    """Extract project/package name from pyproject.toml or setup.py."""
    repo_root = repo_root.resolve()

    # pyproject.toml [project] name = "..."
    pyproject = repo_root / "pyproject.toml"
    if pyproject.exists():
        try:
            content = pyproject.read_text(encoding="utf-8", errors="ignore")
            m = re.search(r'\[project\]\s*\n.*?name\s*=\s*["\']([^"\']+)["\']', content, re.DOTALL)
            if m:
                return m.group(1).lower().replace("-", "_")
        except OSError:
            pass

    # setup.py - name="..." or name='...'
    setup_py = repo_root / "setup.py"
    if setup_py.exists():
        try:
            content = setup_py.read_text(encoding="utf-8", errors="ignore")
            m = re.search(r'name\s*=\s*["\']([^"\']+)["\']', content)
            if m:
                return m.group(1).lower().replace("-", "_")
        except OSError:
            pass

    return None


def _is_framework_repo(repo_root: Path) -> bool:
    """Return True if this repo is a framework (integrations library) - skip Shadow AI."""
    name = _get_project_name(repo_root)
    if name and name in FRAMEWORK_PACKAGE_NAMES:
        return True
    # Also check known substrings (e.g. llama-index-integrations)
    if name:
        for fw in FRAMEWORK_PACKAGE_NAMES:
            if fw in name or name in fw:
                return True
    return False


def _get_ai_api_usage_in_code(repo_root: Path) -> Dict[str, List[Tuple[str, Optional[int]]]]:
    """
    Scan Python files for AI API usage (openai.ChatCompletion, anthropic.Client, etc).
    Returns dict: module -> [(file_path, line), ...].
    """
    used: Dict[str, List[Tuple[str, Optional[int]]]] = {}

    def _add(mod: str, file_path: str, line: Optional[int]) -> None:
        if mod not in used:
            used[mod] = []
        used[mod].append((file_path, line))

    def visit(call: ast.Call, file_path: str, line: Optional[int]) -> None:
        chain = get_call_target_chain(call)
        if not chain:
            return
        chain_lower = [c.lower() for c in chain]
        first = chain_lower[0]
        if first in AI_API_MODULE_TO_PACKAGES:
            _add(first, file_path, line)
        else:
            for mod in AI_API_MODULE_TO_PACKAGES:
                if mod in chain_lower:
                    _add(mod, file_path, line)
                    break

    scan_ast(repo_root, visit)

    def _extract_str_arg(arg: ast.AST) -> Optional[str]:
        """Extract string from ast.Constant or ast.Str (for dynamic import args)."""
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            return arg.value
        if hasattr(ast, "Str") and isinstance(arg, ast.Str):
            return arg.s
        return None

    # Also scan imports and dynamic imports
    for path in walk_python_files(repo_root):
        try:
            rel = str(path.relative_to(repo_root))
            tree = ast.parse(path.read_text(encoding="utf-8", errors="ignore"))
        except (SyntaxError, OSError, ValueError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    full_mod = alias.name.lower()
                    mod = full_mod.split(".")[0]
                    if mod in AI_API_MODULE_TO_PACKAGES:
                        _add(mod, rel, getattr(node, "lineno", None))
                    elif "generativeai" in full_mod or "genai" in full_mod:
                        _add("generativeai", rel, getattr(node, "lineno", None))
            elif isinstance(node, ast.ImportFrom) and node.module:
                mod = node.module.split(".")[0].lower()
                if mod in AI_API_MODULE_TO_PACKAGES:
                    _add(mod, rel, getattr(node, "lineno", None))
                elif "generativeai" in node.module.lower():
                    _add("generativeai", rel, getattr(node, "lineno", None))
                elif "vertexai" in node.module.lower():
                    _add("vertexai", rel, getattr(node, "lineno", None))
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
                first = mod_str.split(".")[0].lower()
                if first in AI_API_MODULE_TO_PACKAGES:
                    _add(first, rel, getattr(node, "lineno", None))
                elif "generativeai" in mod_str.lower() or "genai" in mod_str.lower():
                    _add("generativeai", rel, getattr(node, "lineno", None))
                elif "vertexai" in mod_str.lower():
                    _add("vertexai", rel, getattr(node, "lineno", None))

    return used


def detect_shadow_ai(repo_root: Path) -> DetectionResult:
    """
    Detect Shadow AI: AI API used in code but NOT declared in dependency manifests.

    - Extracts declared deps from requirements.txt, pyproject.toml, setup.py
    - Scans code for openai, anthropic, cohere, vertexai, etc.
    - shadow_ai = True when API in code AND package not in manifests
    - Skips framework repositories (llama-index, langchain, etc.)
    """
    repo_root = Path(repo_root).resolve()

    # Skip framework repos
    if _is_framework_repo(repo_root):
        return DetectionResult(
            component="Shadow AI",
            confidence="low",
            evidence=[],
            details={"detected": False, "skipped": True, "reason": "framework_repository"},
        )

    declared = _get_declared_deps(repo_root)
    used_with_locs = _get_ai_api_usage_in_code(repo_root)
    used_modules = set(used_with_locs.keys())

    shadow_apis: List[str] = []
    evidence: List[str] = []

    for mod in used_modules:
        packages = AI_API_MODULE_TO_PACKAGES.get(mod, set())
        declared_any = any(p.replace("-", "_") in declared for p in packages)
        if not declared_any:
            shadow_apis.append(mod)
            locs = used_with_locs[mod]
            loc_str = ", ".join(f"{f}:{l}" if l else f for f, l in locs[:5])
            if len(locs) > 5:
                loc_str += f" (+{len(locs) - 5} more)"
            evidence.append(f"{mod} used in code but not in manifests — {loc_str}")

    if not shadow_apis:
        return DetectionResult(
            component="Shadow AI",
            confidence="low",
            evidence=[],
            details={"detected": False, "declared_deps": sorted(declared), "used_modules": sorted(used_modules)},
        )

    confidence = "high" if len(shadow_apis) >= 2 else "medium"
    return DetectionResult(
        component="Shadow AI",
        confidence=confidence,
        evidence=evidence[:10],
        details={
            "detected": True,
            "shadow_apis": shadow_apis,
            "declared_deps": sorted(declared),
            "used_but_undeclared": shadow_apis,
        },
    )
