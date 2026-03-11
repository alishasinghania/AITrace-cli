"""
AITrace configuration loaded from aitrace.yaml.

Supports ignore_paths for excluding non-production code from AI analysis.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional

# Always ignored (env, build artifacts) - not configurable
BUILTIN_IGNORE = frozenset({
    "venv", ".venv", "site-packages", "node_modules", ".git",
    "dist", "build", "egg-info", ".eggs", "__pycache__",
})

# Default non-production paths (configurable via aitrace.yaml)
DEFAULT_IGNORE_PATHS = [
    "examples",
    "test",
    "tests",
    "docs",
    "experimental",
    "integrations",
    "packs",
    "demo",
]
IGNORE_PATHS = DEFAULT_IGNORE_PATHS  # Alias for global config

# Cache: repo_root -> effective ignore path parts
_config_cache: Dict[Path, frozenset] = {}


def load_aitrace_config(repo_root: Path) -> dict:
    """
    Load aitrace.yaml from repo root or parent directories.
    Returns empty dict if not found or invalid.
    """
    repo_root = Path(repo_root).resolve()
    for candidate in [repo_root, repo_root.parent]:
        config_path = candidate / "aitrace.yaml"
        if config_path.exists() and config_path.is_file():
            try:
                import yaml
                raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
                return raw if isinstance(raw, dict) else {}
            except Exception:
                return {}
    return {}


def get_ignore_paths(repo_root: Path) -> frozenset:
    """
    Get effective set of path parts to ignore during scanning.
    Merges builtin, defaults, and user config from aitrace.yaml.
    """
    repo_root = Path(repo_root).resolve()
    if repo_root in _config_cache:
        return _config_cache[repo_root]

    config = load_aitrace_config(repo_root)
    user_paths: Optional[List[str]] = config.get("ignore_paths")
    if user_paths is not None and isinstance(user_paths, list):
        ignore_parts = frozenset(str(p) for p in user_paths if isinstance(p, str))
    else:
        ignore_parts = frozenset(DEFAULT_IGNORE_PATHS)

    effective = BUILTIN_IGNORE | ignore_parts
    _config_cache[repo_root] = effective
    return effective


def clear_config_cache() -> None:
    """Clear the config cache (e.g. for tests)."""
    _config_cache.clear()
