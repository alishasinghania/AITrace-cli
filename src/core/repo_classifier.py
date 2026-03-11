"""
Repository classifier for AITrace.

Classifies a scanned repository as application, library, or framework
to reduce false positives in risk scoring.
"""

from __future__ import annotations

import ast
from pathlib import Path

# Entry-point files that indicate an application
APP_ENTRY_POINTS = ("app.py", "main.py", "server.py", "wsgi.py", "run.py", "manage.py")

# Directories that suggest a framework (integrations library, plugins ecosystem)
FRAMEWORK_DIRS = ("integrations", "plugins", "providers", "adapters")

# Directories often present in framework repos
FRAMEWORK_SUPPORT_DIRS = ("examples", "docs", "experimental")


def _count_subdirs(path: Path) -> int:
    """Count direct subdirectories (non-hidden)."""
    if not path.exists() or not path.is_dir():
        return 0
    return sum(1 for p in path.iterdir() if p.is_dir() and not p.name.startswith("."))


def _should_skip_for_classifier(path: Path, repo_root: Path) -> bool:
    """Skip venv, site-packages, tests when scanning for app patterns."""
    try:
        rel = path.relative_to(repo_root)
    except ValueError:
        return True
    parts = set(rel.parts)
    if parts & {"venv", ".venv", "site-packages", "node_modules", ".git"}:
        return True
    if "test" in parts or "tests" in parts:
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


def classify_repository(repo_root: Path) -> str:
    """
    Classify the repository type based on heuristics.

    Returns:
        "application" - Runnable app (app.py, main.py, FastAPI/Flask)
        "library"     - Package for distribution (setup.py, pyproject.toml)
        "framework"   - Integrations/plugins ecosystem
    """
    repo_root = Path(repo_root).resolve()

    # 1. Application indicators (highest priority)
    for name in APP_ENTRY_POINTS:
        if (repo_root / name).exists():
            return "application"

    # FastAPI/Flask with app creation
    if _has_fastapi_or_flask(repo_root):
        return "application"

    # 2. Framework indicators
    for d in FRAMEWORK_DIRS:
        integrations_path = repo_root / d
        if integrations_path.exists() and integrations_path.is_dir():
            # Large integrations dir (e.g. llama-index style) = framework
            subcount = _count_subdirs(integrations_path)
            if subcount >= 5:
                return "framework"
            if subcount >= 2 and (repo_root / "examples").exists():
                return "framework"

    # examples/ + docs/ together often indicate framework repo
    if (repo_root / "examples").exists() and (repo_root / "docs").exists():
        # Check for multiple integration-style packages
        src = repo_root / "src"
        if src.exists():
            subdirs = [p for p in src.iterdir() if p.is_dir() and not p.name.startswith(".")]
            if len(subdirs) >= 3:
                return "framework"

    # plugins/ directory
    if (repo_root / "plugins").exists():
        return "framework"

    # 3. Library (default when packaging present)
    if (repo_root / "setup.py").exists() or (repo_root / "pyproject.toml").exists():
        return "library"

    # 4. Fallback: application if nothing else
    return "application"
