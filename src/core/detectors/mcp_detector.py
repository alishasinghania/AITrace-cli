"""
MCP (Model Context Protocol) server detector.

Detects MCP server configurations from .cursor/mcp.json, mcp.json, .mcp.json.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from .base import DetectionResult

MCP_CONFIG_PATHS = (".cursor/mcp.json", "mcp.json", ".mcp.json")


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
