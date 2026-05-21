"""
Repository classifier for AITrace.

Classifies a scanned repository as application, library, or framework
to reduce false positives in risk scoring.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

# Entry-point files that indicate an application (standalone runnable app)
APP_ENTRY_POINTS = ("app.py", "main.py", "server.py", "wsgi.py", "run.py", "manage.py")

# Directories that suggest a framework (integrations library, plugins ecosystem)
FRAMEWORK_DIRS = ("integrations", "plugins", "providers", "adapters")

# Package name patterns that indicate known frameworks (llama-index, langchain, etc.)
KNOWN_FRAMEWORK_PATTERNS = (
    r"llama-?index",
    r"langchain",
    r"langgraph",
    r"haystack",
    r"semantic-kernel",
    r"crewai",
    r"^autogen$",  # Microsoft AutoGen
)

# README phrasing that suggests repo type (checked in first ~200 lines)
# Prefer phrases where the repo itself is described, not "built with X"
README_FRAMEWORK_PHRASES = (
    r"\b(is|,\s*)\s*(a|an|the)\s+(?:open[- ]?source\s+)?framework\b",
    r"\bframework\s+for\s+(?:building|developing|creating)\b",
    r"\b(is|,\s*)\s*(a|an)\s+(?:llm|ai|data|agent)\s+framework\b",
)
README_LIBRARY_PHRASES = (
    r"\b(is|,\s*)\s*(a|an)\s+(?:python\s+)?library\b",
    r"\bprovides\s+(?:a\s+)?(?:python\s+)?library\b",
)
README_APPLICATION_PHRASES = (
    r"\bstandalone\s+application\b",
    r"\b(is|,\s*)\s*(a|an)\s+application\b",
)


def _count_subdirs(path: Path) -> int:
    """Count direct subdirectories (non-hidden)."""
    if not path.exists() or not path.is_dir():
        return 0
    return sum(1 for p in path.iterdir() if p.is_dir() and not p.name.startswith("."))


def _should_skip_for_classifier(path: Path, repo_root: Path) -> bool:
    """Skip venv, site-packages, tests, examples when scanning for app patterns."""
    try:
        rel = path.relative_to(repo_root)
    except ValueError:
        return True
    parts = set(rel.parts)
    if parts & {"venv", ".venv", "site-packages", "node_modules", ".git"}:
        return True
    if "test" in parts or "tests" in parts or "examples" in parts:
        return True
    return False


def _is_known_framework(repo_root: Path) -> bool:
    """Detect known framework packages via pyproject.toml or setup.py."""
    for config_file in ("pyproject.toml", "setup.py", "setup.cfg"):
        path = repo_root / config_file
        if not path.exists():
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        content_lower = content.lower()

        # pyproject.toml: only get name from [project] section (avoid authors' "name = ...")
        if config_file == "pyproject.toml":
            project_match = re.search(r"\[project\]\s*(.*?)(?=\[|\Z)", content_lower, re.DOTALL)
            if project_match:
                project_section = project_match.group(1)
            else:
                project_section = content_lower
        else:
            project_section = content_lower

        # Extract package name: name = "llama-index" or name='llama-index'
        name_match = re.search(r'name\s*=\s*["\']([^"\']+)["\']', project_section)
        if name_match:
            pkg_name = name_match.group(1).lower().replace("_", "-")
            for pattern in KNOWN_FRAMEWORK_PATTERNS:
                if re.search(pattern, pkg_name):
                    return True
    return False


def _has_fastapi_or_flask(repo_root: Path) -> bool:
    """Detect FastAPI or Flask app creation in Python files."""
    for py_path in repo_root.rglob("*.py"):
        if _should_skip_for_classifier(py_path, repo_root):
            continue
        try:
            content = py_path.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(content)
        except (SyntaxError, OSError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    if node.func.id in ("FastAPI", "Flask"):
                        return True
                elif isinstance(node.func, ast.Attribute):
                    if node.func.attr in ("FastAPI", "Flask"):
                        return True
    return False


def _readme_suggests_type(repo_root: Path) -> str | None:
    """
    Check README.md for explicit repo type descriptions.

    Returns "framework", "library", "application", or None if no clear signal.
    Only scans the first ~200 lines (intro section) to avoid false matches.
    """
    for name in ("README.md", "README.MD", "readme.md", "README.rst", "README"):
        readme_path = repo_root / name
        if not readme_path.exists() or not readme_path.is_file():
            continue
        try:
            content = readme_path.read_text(encoding="utf-8", errors="ignore").lower()
        except OSError:
            continue
        # Use first ~200 lines (intro usually states what the project is)
        lines = content.splitlines()[:200]
        intro = "\n".join(lines)

        for pattern in README_FRAMEWORK_PHRASES:
            if re.search(pattern, intro, re.IGNORECASE):
                return "framework"
        for pattern in README_LIBRARY_PHRASES:
            if re.search(pattern, intro, re.IGNORECASE):
                return "library"
        for pattern in README_APPLICATION_PHRASES:
            if re.search(pattern, intro, re.IGNORECASE):
                return "application"
        break  # Only check first README variant found
    return None


def classify_repository(repo_root: Path) -> str:
    """
    Classify the repository type based on heuristics and README.md.

    Uses structure (pyproject, dirs, entry points) and README phrasing to
    confirm or override. Framework is checked first because framework repos
    often have app-like demos that would otherwise trigger application.

    Returns:
        "application" - Runnable app
        "library"     - Package for distribution
        "framework"   - Integrations/plugins ecosystem
    """
    repo_root = Path(repo_root).resolve()
    readme_type = _readme_suggests_type(repo_root)

    # 1. Framework indicators (structure - frameworks often have app-like demos)
    if _is_known_framework(repo_root):
        return "framework"

    for d in FRAMEWORK_DIRS:
        framework_path = repo_root / d
        if framework_path.exists() and framework_path.is_dir():
            subcount = _count_subdirs(framework_path)
            if subcount >= 5:
                return "framework"
            if subcount >= 2 and (repo_root / "examples").exists():
                return "framework"

    # Check for *-integrations style dirs (e.g. llama-index-integrations)
    for item in repo_root.iterdir():
        if item.is_dir() and not item.name.startswith("."):
            if "integrations" in item.name.lower():
                subcount = _count_subdirs(item)
                if subcount >= 5:
                    return "framework"
                if subcount >= 2 and (repo_root / "examples").exists():
                    return "framework"

    if (repo_root / "examples").exists() and (repo_root / "docs").exists():
        src = repo_root / "src"
        if src.exists():
            subdirs = [p for p in src.iterdir() if p.is_dir() and not p.name.startswith(".")]
            if len(subdirs) >= 3:
                return "framework"

    if (repo_root / "plugins").exists():
        return "framework"

    # 3. Application indicators
    for name in APP_ENTRY_POINTS:
        if (repo_root / name).exists():
            # README can override: frameworks often have app-like demos
            if readme_type == "framework":
                return "framework"
            return "application"

    if _has_fastapi_or_flask(repo_root):
        if readme_type == "framework":
            return "framework"
        return "application"

    # 4. Library (package for distribution)
    if (repo_root / "setup.py").exists() or (repo_root / "pyproject.toml").exists():
        if readme_type == "framework":
            return "framework"
        if readme_type == "library":
            return "library"
        return "library"

    # 5. Fallback - use README if it explicitly states type
    if readme_type:
        return readme_type
    return "application"
