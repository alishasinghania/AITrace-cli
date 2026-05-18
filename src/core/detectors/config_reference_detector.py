"""
Config and string reference detector.

Detects AI provider references in config files, string literals, and URLs
that are not caught by import or AST call analysis (e.g. aibommaker-style
metadata with provider names in dicts).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Optional, Set, Tuple

from ..config import get_ignore_paths

# API URL patterns -> provider (for config/string detection)
API_URL_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"api\.openai\.com", re.I), "openai"),
    (re.compile(r"api\.anthropic\.com", re.I), "anthropic"),
    (re.compile(r"generativelanguage\.googleapis\.com", re.I), "google-generativeai"),
    (re.compile(r"ai\.google\.dev", re.I), "google-generativeai"),
    (re.compile(r"api\.cohere\.(ai|com)", re.I), "cohere"),
    (re.compile(r"api\.mistral\.ai", re.I), "mistralai"),
    (re.compile(r"api\.replicate\.com", re.I), "replicate"),
    (re.compile(r"localhost:11434|ollama[./]|[\"']ollama[\"']|OLLAMA_", re.I), "ollama"),  # Ollama local API
    (re.compile(r"api\.ai21\.(com|ai)", re.I), "ai21"),
    (re.compile(r"api\.fireworks\.ai", re.I), "fireworks-ai"),
    (re.compile(r"api\.aleph-alpha\.com", re.I), "aleph-alpha-client"),
]

# Model ID patterns in strings -> provider (for metadata/config)
MODEL_ID_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'["\']gpt-4(?:o|o-mini|-turbo)?["\']', re.I), "openai"),
    (re.compile(r'["\']gpt-3\.5-turbo(?:-\d+)?["\']', re.I), "openai"),
    (re.compile(r'["\']o1(?:-preview|-mini)?["\']', re.I), "openai"),
    (re.compile(r'["\']text-embedding-3-(?:large|small)["\']', re.I), "openai"),
    (re.compile(r'["\']text-embedding-ada-002["\']', re.I), "openai"),
    (re.compile(r'["\']claude-3(?:\.5-sonnet|-opus|-sonnet|-haiku)?(?:-\d+)?["\']', re.I), "anthropic"),
    (re.compile(r'["\']gemini-1\.5-(?:pro|flash)["\']', re.I), "google-generativeai"),
    (re.compile(r'["\']gemini-2\.0-flash-exp["\']', re.I), "google-generativeai"),
    (re.compile(r'["\']gemini-pro["\']', re.I), "google-generativeai"),
    (re.compile(r'["\'](?:mistral-large|mixtral(?:-8x7b)?(?:-\d+)?)["\']', re.I), "mistralai"),
    (re.compile(r'["\']llama3?(?:-\d+b)?(?:-\d+)?["\']', re.I), "ollama"),
]

# Provider key in config (e.g. "provider": "openai")
PROVIDER_KEY_PATTERN = re.compile(
    r'["\']?(?:provider|api_provider|llm_provider)["\']?\s*:\s*["\']([a-z0-9\-]+)["\']',
    re.I,
)
KNOWN_PROVIDER_VALUES = {"openai", "anthropic", "cohere", "google", "mistral", "mistralai", "replicate", "together", "groq", "ollama", "ai21", "fireworks", "fireworks-ai", "aleph-alpha", "aleph_alpha"}


def detect_config_references(repo_root: Path) -> Set[Tuple[str, str]]:
    """
    Scan config files and source files for AI provider references in strings/URLs.
    Returns set of (provider, file_path).
    """
    repo_root = Path(repo_root).resolve()
    ignore_parts = get_ignore_paths(repo_root)
    found: Set[Tuple[str, str]] = set()

    exts = {".py", ".yaml", ".yml", ".json", ".env", ".toml", ".cfg", ".ini"}
    for path in repo_root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in exts:
            continue
        try:
            rel = path.relative_to(repo_root)
        except ValueError:
            continue
        if set(rel.parts) & ignore_parts:
            continue
        if any(p in rel.parts for p in ("venv", ".venv", "node_modules", ".git", "site-packages")):
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        # API URL patterns
        for pat, provider in API_URL_PATTERNS:
            if pat.search(content):
                found.add((provider, str(rel)))
                break

        # Model ID patterns
        for pat, provider in MODEL_ID_PATTERNS:
            if pat.search(content):
                found.add((provider, str(rel)))
                break

        # Provider key: "provider": "openai"
        for m in PROVIDER_KEY_PATTERN.finditer(content):
            val = m.group(1).lower()
            if val in KNOWN_PROVIDER_VALUES:
                provider = (
                    "google-generativeai" if val == "google"
                    else "mistralai" if val == "mistral"
                    else "aleph-alpha-client" if val in ("aleph-alpha", "aleph_alpha")
                    else val
                )
                found.add((provider, str(rel)))
                break

    return found


def detect_model_references(repo_root: Path) -> List[Tuple[str, str, str, Optional[int]]]:
    """
    Scan config and source files for AI model ID references (e.g. gpt-4o, claude-3-opus).
    Returns list of (provider, model_id, file_path, line_number).
    """
    repo_root = Path(repo_root).resolve()
    ignore_parts = get_ignore_paths(repo_root)
    found: List[Tuple[str, str, str, Optional[int]]] = []
    seen: Set[Tuple[str, str, Optional[int]]] = set()

    exts = {".py", ".yaml", ".yml", ".json", ".env", ".toml", ".cfg", ".ini"}
    for path in repo_root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in exts:
            continue
        try:
            rel = path.relative_to(repo_root)
        except ValueError:
            continue
        if set(rel.parts) & ignore_parts:
            continue
        if any(p in rel.parts for p in ("venv", ".venv", "node_modules", ".git", "site-packages")):
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue

        rel_str = str(rel)
        for line_no, line in enumerate(lines, 1):
            for pat, provider in MODEL_ID_PATTERNS:
                for m in pat.finditer(line):
                    model_id = m.group(0).strip("\"'`")
                    key = (provider, model_id, rel_str, line_no)
                    if key not in seen:
                        seen.add(key)
                        found.append((provider, model_id, rel_str, line_no))

    return found
