"""Shared AST utilities for architecture detectors."""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Callable, List, Optional

# Additional path parts (beyond config ignore_paths) - always applied
EXTRA_IGNORED_PARTS = {"__tests__"}
IGNORED_FILE_PATTERNS = (r"_test\.py$", r"test_.*\.py$", r"conftest\.py$")


def should_skip_path(path: Path, repo_root: Path) -> bool:
    """
    Skip non-production files before AST scanning.
    Uses aitrace.yaml ignore_paths (examples, tests, docs, etc.) plus builtins.
    """
    try:
        rel = path.relative_to(repo_root)
    except ValueError:
        return True

    from ..config import get_ignore_paths

    ignore_parts = get_ignore_paths(repo_root) | EXTRA_IGNORED_PARTS
    if set(rel.parts) & ignore_parts:
        return True
    # Skip AITrace's own detectors (avoid self-detection)
    parts = rel.parts
    if "core" in parts and "detectors" in parts:
        return True
    for pat in IGNORED_FILE_PATTERNS:
        if re.search(pat, path.name):
            return True
    return False


def get_call_target(node: ast.Call) -> Optional[str]:
    """Extract call target name (attr or id) for pattern matching."""
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    if isinstance(node.func, ast.Name):
        return node.func.id
    return None


def get_call_target_chain(node: ast.Call) -> List[str]:
    """Get full chain e.g. ['openai', 'ChatCompletion', 'create']."""
    chain: List[str] = []
    n = node.func
    while isinstance(n, ast.Attribute):
        chain.append(n.attr)
        n = n.value
    if isinstance(n, ast.Name):
        chain.append(n.id)
    return list(reversed(chain))


def walk_python_files(repo_root: Path) -> List[Path]:
    """Yield Python files, excluding ignored paths."""
    out: List[Path] = []
    for path in repo_root.rglob("*.py"):
        if not should_skip_path(path, repo_root):
            out.append(path)
    return out


def scan_ast(
    repo_root: Path,
    visit_call: Callable[[ast.Call, str, Optional[int]], None],
) -> None:
    """Walk all Python files and call visit_call for each Call node."""
    for path in walk_python_files(repo_root):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="ignore"))
        except (SyntaxError, OSError):
            continue
        rel = str(path.relative_to(repo_root))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                visit_call(node, rel, getattr(node, "lineno", None))
