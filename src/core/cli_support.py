from __future__ import annotations

from pathlib import Path
from typing import Optional


def resolve_repo_path(path: str | None) -> Path:
    if path is None:
        return Path.cwd()
    return Path(path).expanduser().resolve()


def find_default_policy(repo_root: Path) -> Optional[Path]:
    """
    Look for a policy.yaml file starting from the repo root.
    """
    candidate = repo_root / "policy.yaml"
    if candidate.exists():
        return candidate
    return None

