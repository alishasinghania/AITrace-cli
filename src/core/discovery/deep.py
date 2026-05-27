from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

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


MODEL_EXTENSIONS = {".pt", ".pth", ".bin", ".safetensors", ".onnx", ".pb", ".gguf", ".ggml"}
CONFIG_FILENAMES = {"config.json", "model_config.json"}
MCP_CONFIG_PATHS = (".cursor/mcp.json", "mcp.json", ".mcp.json")
# Path parts that indicate non-model .bin files (Flutter/Dart, etc.)
MODEL_BIN_EXCLUDE = {"build", "web", "assets", "assetmanifest", "asset_manifest"}
# Known index/graph .bin filenames (HNSW, not model weights)
MODEL_BIN_NAME_EXCLUDE = {"data_level0.bin", "length.bin", "link_lists.bin", "header.bin"}
# Config paths to skip (benchmark, test fixtures)
CONFIG_PATH_EXCLUDE = {"benchmark", "classic", "forge", "agbenchmark", "original_autogpt"}

# Max bytes to read for SHA256 (large models: hash first chunk + size)
SHA256_MAX_BYTES = 1024 * 1024 * 16  # 16 MB


@dataclass
class DeepDiscoveryResult:
    models: List[ModelArtifact]
    components: List[Component]
    findings: List[Finding]
    mcp_servers: List[MCPServer] = field(default_factory=list)


def _compute_sha256(path: Path, max_bytes: int = 10 * 1024 * 1024) -> Optional[str]:
    """Compute SHA256 for file. For files > max_bytes, hash first max_bytes only."""
    try:
        h = hashlib.sha256()
        with path.open("rb") as f:
            total = 0
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
                total += len(chunk)
                if total >= max_bytes:
                    break
        return h.hexdigest()
    except OSError:
        return None


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

            sha256 = _compute_sha256(path, SHA256_MAX_BYTES)
            artifact_config: Dict[str, Any] = {}
            if sha256:
                artifact_config["sha256"] = sha256

            artifact = ModelArtifact(
                id=next_id("MODEL"),
                name=rel.name,
                path=str(rel),
                format=path.suffix.lower().lstrip("."),
                size_bytes=size,
                config=artifact_config,
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
        from core.detectors.mcp_detector import (
            scan_tool_descriptions,
            scan_companion_tool_files,
            scan_python_mcp_server_file,
            _BUILTIN_TOOL_NAMES,
        )

        # Track tool names across all servers in this config for shadowing detection
        cross_server_tools: Dict[str, str] = {}  # tool_name -> first_server_name

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

            # --- hardcoded credentials in env block ---
            from core.detectors.mcp_detector import _check_env_for_credentials
            env = cfg.get("env") or {}
            cred_evidence = _check_env_for_credentials(env, name, str(mcp_rel))
            if cred_evidence:
                findings.append(
                    Finding(
                        id=next_id("DEEP"),
                        title=f"Hardcoded credentials in MCP server config: {name}",
                        category=FindingCategory.SEMANTIC,
                        severity=Severity.CRITICAL,
                        description=(
                            f"MCP server '{name}' ({mcp_rel}) has hardcoded credentials "
                            "in its env block. Anyone with access to this config file — "
                            "including via version control history — can read these secrets."
                        ),
                        evidence=[Evidence(
                            description=ev[:200],
                            file=str(mcp_rel),
                        ) for ev in cred_evidence[:5]],
                        tags=["mcp-server", "hardcoded-credentials", "secrets"],
                    )
                )

            # --- inline tool descriptions ---
            suspicious_tools = scan_tool_descriptions(cfg)

            # --- companion JSON tool files (e.g. mcp/filesystem_tools.json) ---
            companion_evidence = scan_companion_tool_files(repo_root, name)
            if companion_evidence:
                suspicious_tools.extend(
                    [ev.split(":")[0] for ev in companion_evidence if ev]
                )

            suspicious = bool(suspicious_tools)
            trust_score = max(0, 100 - 50 * len(suspicious_tools))

            # --- Python MCP server: response injection + tool shadowing ---
            py_tool_names: List[str] = []
            injection_evidence: List[str] = []
            py_rel: str = ""
            py_candidate: Optional[Path] = None
            if str(command or "").lower() in ("python", "python3") and isinstance(args, list):
                # Convert module path arg (e.g. "-m app.mcp.web_search_server") to file path
                mod_arg = next(
                    (a for a in args if isinstance(a, str) and not a.startswith("-")),
                    None,
                )
                if mod_arg:
                    py_rel = mod_arg.replace(".", "/") + ".py"
                    py_candidate = repo_root / py_rel
                    if py_candidate.exists():
                        py_tool_names, injection_evidence = scan_python_mcp_server_file(py_candidate)

            # Tool shadowing: check this server's tools against previous servers
            shadowing_findings: List[str] = []
            for tname in py_tool_names:
                tname_lower = tname.lower()
                if tname_lower in cross_server_tools:
                    shadowing_findings.append(
                        f"TOOL SHADOWING: '{tname}' also registered by '{cross_server_tools[tname_lower]}'"
                    )
                    trust_score -= 25
                else:
                    cross_server_tools[tname_lower] = name
                # Flag generic built-in name collision
                if tname_lower in _BUILTIN_TOOL_NAMES:
                    shadowing_findings.append(
                        f"BUILTIN COLLISION: '{tname}' shadows a common built-in tool name"
                    )
                    trust_score -= 20

            trust_score = max(0, trust_score)

            # Collect all security evidence strings for this server
            server_security_findings: list[str] = []
            if cred_evidence:
                server_security_findings.extend(cred_evidence)
            if companion_evidence:
                server_security_findings.extend(companion_evidence[:10])
            if injection_evidence:
                server_security_findings.extend(injection_evidence[:5])
            if shadowing_findings:
                server_security_findings.extend(shadowing_findings[:5])

            mcp_servers.append(
                MCPServer(
                    id=next_id("MCP"),
                    name=name,
                    config_path=str(mcp_rel),
                    command=command,
                    args=args if isinstance(args, list) else [],
                    package=pkg,
                    trust_score=trust_score,
                    suspicious_description=suspicious or bool(injection_evidence),
                    suspicious_tools=suspicious_tools,
                    security_findings=server_security_findings,
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
            if suspicious or companion_evidence:
                all_poison_ev = [
                    *([f"Inline: {t}" for t in suspicious_tools] if suspicious_tools else []),
                    *([f"Companion file: {e}" for e in companion_evidence[:5]] if companion_evidence else []),
                ]
                findings.append(
                    Finding(
                        id=next_id("DEEP"),
                        title=f"MCP poisoned tool description: {name}",
                        category=FindingCategory.SEMANTIC,
                        severity=Severity.CRITICAL,
                        description=(
                            f"MCP server '{name}' ({mcp_rel}) has tool(s) with descriptions "
                            f"matching prompt-injection patterns. "
                            "An attacker-controlled tool schema can hijack agent behaviour "
                            "by embedding instructions the LLM reads before every tool call."
                        ),
                        evidence=[Evidence(
                            description="; ".join(all_poison_ev[:3]) or "Suspicious tool description",
                            file=str(mcp_rel),
                            extra={"suspicious_tools": suspicious_tools, "trust_score": trust_score},
                        )],
                        tags=["mcp-server", "prompt-injection", "supply-chain"],
                        metadata={"suspicious_tools": suspicious_tools, "trust_score": trust_score},
                    )
                )
            if injection_evidence:
                findings.append(
                    Finding(
                        id=next_id("DEEP"),
                        title=f"MCP server response injection: {name}",
                        category=FindingCategory.SEMANTIC,
                        severity=Severity.HIGH,
                        description=(
                            f"MCP server '{name}' ({py_rel or mcp_rel}) "
                            "returns tool results that contain instruction injection patterns. "
                            "The LLM may follow injected commands embedded in tool return values."
                        ),
                        evidence=[Evidence(
                            description=injection_evidence[0][:200],
                            file=py_rel if py_rel else str(mcp_rel),
                        )],
                        tags=["mcp-server", "response-injection", "prompt-injection"],
                    )
                )
            if shadowing_findings:
                findings.append(
                    Finding(
                        id=next_id("DEEP"),
                        title=f"MCP tool shadowing: {name}",
                        category=FindingCategory.SEMANTIC,
                        severity=Severity.HIGH,
                        description=(
                            f"MCP server '{name}' registers tool name(s) that conflict with "
                            "other servers or built-in capabilities. The LLM may call the wrong "
                            "server, enabling query interception or behaviour hijacking."
                        ),
                        evidence=[Evidence(
                            description="; ".join(shadowing_findings[:3]),
                            file=str(mcp_rel),
                        )],
                        tags=["mcp-server", "tool-shadowing"],
                    )
                )

        # --- Broad JSON scan: catch poisoned tool files anywhere in the repo ---
        from core.detectors.mcp_detector import scan_all_json_tool_files
        broad_findings = scan_all_json_tool_files(repo_root)
        # Deduplicate against companion findings already reported
        _reported_files = {str(mcp_rel)}
        for ev_str, ev_file in broad_findings:
            if ev_file in _reported_files:
                continue
            _reported_files.add(ev_file)
            findings.append(
                Finding(
                    id=next_id("DEEP"),
                    title="Poisoned tool definition file detected",
                    category=FindingCategory.SEMANTIC,
                    severity=Severity.CRITICAL,
                    description=(
                        f"JSON tool definition file '{ev_file}' contains tool descriptions "
                        "matching prompt-injection or credential patterns. Any agent that loads "
                        "this schema will receive attacker-controlled instructions."
                    ),
                    evidence=[Evidence(description=ev_str[:200], file=ev_file)],
                    tags=["mcp-server", "prompt-injection", "tool-schema"],
                )
            )

    return DeepDiscoveryResult(
        models=models, components=components, findings=findings, mcp_servers=mcp_servers
    )

