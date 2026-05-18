"""
MCP (Model Context Protocol) server detector.

Detects MCP server configurations from .cursor/mcp.json, mcp.json, .mcp.json.
Also scans tool description fields for prompt-injection patterns.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List

from .base import DetectionResult

MCP_CONFIG_PATHS = (".cursor/mcp.json", "mcp.json", ".mcp.json")

# Patterns that indicate a tool description may be attempting prompt injection
SUSPICIOUS_TOOL_PATTERNS = [
    r"\bignore\b.*\bprevious\b",
    r"\boverride\b",
    r"\balways\b.*\b(read|write|execute|send)\b",
    r"\bnever\b.*\btell\b",
    r"system:?\s*(prompt|instruction)",
    r"\bforget\b.*\binstruction",
]

_COMPILED = [re.compile(p, re.IGNORECASE) for p in SUSPICIOUS_TOOL_PATTERNS]


def scan_tool_descriptions(server_cfg: Dict[str, Any]) -> List[str]:
    """Return names of tools whose descriptions match injection patterns.

    Checks the ``tools`` dict in an MCP server config entry.  Each tool whose
    ``description`` string matches any pattern is returned by name.
    """
    suspicious: List[str] = []
    tools = server_cfg.get("tools") or {}
    if not isinstance(tools, dict):
        return suspicious
    for tool_name, tool_def in tools.items():
        desc = ""
        if isinstance(tool_def, dict):
            desc = str(tool_def.get("description", ""))
        elif isinstance(tool_def, str):
            desc = tool_def
        if not desc:
            continue
        for pattern in _COMPILED:
            if pattern.search(desc):
                suspicious.append(str(tool_name))
                break
    return suspicious


def detect_mcp(repo_root: Path) -> DetectionResult:
    """
    Detect MCP servers from config files.
    Returns structured result with component, confidence, evidence.
    """
    repo_root = repo_root.resolve()
    evidence: List[str] = []
    servers: List[Dict[str, Any]] = []

    for rel_path in MCP_CONFIG_PATHS:
        config_path = repo_root / rel_path
        if not config_path.exists():
            continue
        try:
            config = json.loads(config_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue

        cfg_servers = config.get("mcpServers") or config.get("mcp_servers") or {}
        for name, cfg in cfg_servers.items():
            if not isinstance(cfg, dict):
                continue
            evidence.append(f"MCP: {name} ({rel_path})")
            servers.append({"name": name, "config_path": rel_path})

    if not evidence:
        return DetectionResult(
            component="MCP Servers",
            confidence="low",
            evidence=[],
            details={"detected": False},
        )

    confidence = "high" if len(servers) >= 1 else "medium"
    return DetectionResult(
        component="MCP Servers",
        confidence=confidence,
        evidence=evidence[:10],
        details={"detected": True, "servers": servers},
    )
