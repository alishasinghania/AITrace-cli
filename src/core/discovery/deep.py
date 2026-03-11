from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from ..models import (
    Component,
    ComponentType,
    Evidence,
    Finding,
    FindingCategory,
    MCPServer,
    ModelArtifact,
    Severity,
)


MODEL_EXTENSIONS = {".pt", ".bin", ".safetensors", ".onnx", ".pb"}
CONFIG_FILENAMES = {"config.json", "model_config.json"}
MCP_CONFIG_PATHS = (".cursor/mcp.json", "mcp.json", ".mcp.json")
# Path parts that indicate non-model .bin files (Flutter/Dart, etc.)
MODEL_BIN_EXCLUDE = {"build", "web", "assets", "assetmanifest", "asset_manifest"}
# Known index/graph .bin filenames (HNSW, not model weights)
MODEL_BIN_NAME_EXCLUDE = {"data_level0.bin", "length.bin", "link_lists.bin", "header.bin"}
# Config paths to skip (benchmark, test fixtures)
CONFIG_PATH_EXCLUDE = {"benchmark", "classic", "forge", "agbenchmark", "original_autogpt"}


@dataclass
class DeepDiscoveryResult:
    models: List[ModelArtifact]
    components: List[Component]
    findings: List[Finding]
    mcp_servers: List[MCPServer] = field(default_factory=list)


def _infer_framework_from_config(config: Dict) -> Optional[str]:
    if "architectures" in config:
        return "transformers"
    if "hidden_size" in config and "num_attention_heads" in config:
        return "transformers-like"
    if "onnx_opset_version" in config:
        return "onnx"
    return None


def discover_deep(repo_root: Path) -> DeepDiscoveryResult:
    """
    Perform deep inspection of the repository to locate model artefacts and
    basic metadata.
    """
    repo_root = repo_root.resolve()
    models: List[ModelArtifact] = []
    components: List[Component] = []
    findings: List[Finding] = []

    id_counter = 1

    def next_id(prefix: str) -> str:
        nonlocal id_counter
        val = f"{prefix}-{id_counter:04d}"
        id_counter += 1
        return val

    from ..config import get_ignore_paths

    ignore_parts = get_ignore_paths(repo_root)
    for path in repo_root.rglob("*"):
        if not path.is_file():
            continue
        try:
            rel = path.relative_to(repo_root)
        except ValueError:
            continue
        if set(rel.parts) & ignore_parts:
            continue

        # Model binaries (exclude build artifacts like AssetManifest.bin)
        if path.suffix.lower() in MODEL_EXTENSIONS:
            if path.suffix.lower() == ".bin":
                rel_parts = set(p.lower() for p in rel.parts)
                if rel_parts & MODEL_BIN_EXCLUDE or "assetmanifest" in rel.name.lower():
                    continue
                if rel.name.lower() in MODEL_BIN_NAME_EXCLUDE:
                    continue
            size = None
            try:
                size = path.stat().st_size
            except OSError:
                pass

            artifact = ModelArtifact(
                id=next_id("MODEL"),
                name=rel.name,
                path=str(rel),
                format=path.suffix.lower().lstrip("."),
                size_bytes=size,
            )
            models.append(artifact)

            findings.append(
                Finding(
                    id=next_id("DEEP"),
                    title="Model binary discovered",
                    category=FindingCategory.DEEP,
                    severity=Severity.MEDIUM,
                    description=f"Model artefact '{rel}' detected.",
                    evidence=[Evidence(description="File extension inspection", file=str(rel))],
                    tags=["model-artifact"],
                    component_id=artifact.id,
                )
            )

        # Config files (skip benchmark/test configs)
        if rel.name in CONFIG_FILENAMES:
            if set(rel.parts) & CONFIG_PATH_EXCLUDE:
                continue
            try:
                config = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                config = {}

            framework = _infer_framework_from_config(config)
            component = Component(
                id=next_id("CFG"),
                name=rel.name,
                type=ComponentType.MODEL,
                version=None,
                properties={"config": config, "framework": framework},
            )
            components.append(component)

            findings.append(
                Finding(
                    id=next_id("DEEP"),
                    title="Model configuration discovered",
                    category=FindingCategory.DEEP,
                    severity=Severity.INFO,
                    description=f"Model configuration file '{rel}' detected.",
                    component_id=component.id,
                    evidence=[Evidence(description="Config file", file=str(rel))],
                    tags=["model-config"],
                )
            )

    # MCP server config discovery
    mcp_servers: List[MCPServer] = []
    for mcp_rel in MCP_CONFIG_PATHS:
        mcp_path = repo_root / mcp_rel
        if not mcp_path.exists():
            continue
        try:
            config = json.loads(mcp_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        servers = config.get("mcpServers") or config.get("mcp_servers") or {}
        for name, cfg in servers.items():
            if not isinstance(cfg, dict):
                continue
            command = cfg.get("command")
            args = cfg.get("args") or []
            pkg = None
            if isinstance(args, list) and args:
                if "npx" in str(command or "").lower() or "-y" in [str(a) for a in args[:2]]:
                    pkg = args[-1] if len(args) > 1 else name
                elif any("mcp" in str(a).lower() or "modelcontextprotocol" in str(a).lower() for a in args):
                    pkg = next((a for a in args if "mcp" in str(a).lower() or "modelcontextprotocol" in str(a).lower()), name)
            mcp_servers.append(
                MCPServer(
                    id=next_id("MCP"),
                    name=name,
                    config_path=str(mcp_rel),
                    command=command,
                    args=args if isinstance(args, list) else [],
                    package=pkg,
                )
            )
            findings.append(
                Finding(
                    id=next_id("DEEP"),
                    title=f"MCP server discovered: {name}",
                    category=FindingCategory.DEEP,
                    severity=Severity.MEDIUM,
                    description=f"MCP server '{name}' configured in {mcp_rel}.",
                    evidence=[Evidence(description="MCP config file", file=str(mcp_rel))],
                    tags=["mcp-server"],
                )
            )

    return DeepDiscoveryResult(
        models=models, components=components, findings=findings, mcp_servers=mcp_servers
    )

