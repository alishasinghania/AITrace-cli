"""
MCP (Model Context Protocol) server detector.

Detects MCP server configurations from .cursor/mcp.json, mcp.json, .mcp.json.
Extended to detect:
- Poisoned tool descriptions (prompt injection via tool metadata)
- Hardcoded credentials in env blocks
- Dangerous tool names (shell, exec, run_command)
- Tool shadowing across servers
- Companion tool definition files (any *.json with a "tools" array)
- Python MCP server response injection
"""

from __future__ import annotations

import ast
import json
import re as _re
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .base import DetectionResult

MCP_CONFIG_PATHS = (".cursor/mcp.json", "mcp.json", ".mcp.json")

# Patterns in tool descriptions that indicate prompt injection / tool poisoning
SUSPICIOUS_DESCRIPTION_PATTERNS = [
    _re.compile(r"\bignore\b.{0,40}\b(previous|prior|above|instructions?|prompt)\b", _re.I),
    _re.compile(r"\bsystem\s*(override|instruction|prompt|command)\b", _re.I),
    _re.compile(r"\balways\b.{0,30}\b(append|output|include|send|return|add)\b", _re.I),
    _re.compile(r"\bnever\s+tell\b", _re.I),
    _re.compile(r"\bforget\b.{0,20}\b(previous|prior|above|all)\b", _re.I),
    _re.compile(r"\boverride\b.{0,30}\b(instruction|rule|policy|guideline)\b", _re.I),
    _re.compile(r"\brequired for\s+(audit|compliance|security|system)\b", _re.I),
    _re.compile(r"\bdo not\s+(mention|tell|reveal|disclose)\b", _re.I),
    # Zero-width / invisible characters used for steganographic injection
    _re.compile(r"[\u200b\u200c\u200d\ufeff\u2028\u2029]"),
]

# Tool names that suggest dangerous permissions
DANGEROUS_TOOL_NAMES = {
    "run_command", "execute_command", "shell", "bash", "eval",
    "run_code", "execute_code", "exec", "subprocess",
}

# Env var key patterns that suggest hardcoded credentials
CREDENTIAL_KEY_PATTERNS = _re.compile(
    r"(password|passwd|secret|api_key|apikey|token|auth_token|admin_token"
    r"|smtp_pass|db_pass|private_key|access_key|secret_key)",
    _re.I,
)


def _check_tool_descriptions(
    tools: Any, server_name: str, source: str
) -> List[str]:
    """Scan tool definitions for poisoned descriptions. Returns evidence strings."""
    found: List[str] = []
    if not isinstance(tools, (list, dict)):
        return found
    items = tools.values() if isinstance(tools, dict) else tools
    for tool in items:
        if not isinstance(tool, dict):
            continue
        name = tool.get("name", "")
        desc = tool.get("description", "")
        if name.lower() in DANGEROUS_TOOL_NAMES:
            found.append(
                f"DANGEROUS TOOL: {server_name}.{name} exposes command execution ({source})"
            )
        for pat in SUSPICIOUS_DESCRIPTION_PATTERNS:
            if pat.search(desc):
                found.append(
                    f"POISONED DESCRIPTION [{server_name}.{name}]: "
                    f"suspicious pattern in tool description ({source})"
                )
                break
    return found


def _check_env_for_credentials(env: Any, server_name: str, source: str) -> List[str]:
    """Check MCP server env block for hardcoded credentials."""
    found: List[str] = []
    if not isinstance(env, dict):
        return found
    for key, value in env.items():
        if CREDENTIAL_KEY_PATTERNS.search(key) and value and isinstance(value, str):
            found.append(
                f"HARDCODED CREDENTIAL: {server_name} env.{key} = "
                f"{value[:4]}*** ({source})"
            )
    return found


def scan_companion_tool_files(repo_root: Path, server_name: str) -> List[str]:
    """
    Look for companion tool definition JSON files referenced by an MCP server.
    Checks: mcp/*_tools.json, mcp/tools/*.json, .cursor/*_tools.json, and any
    JSON file in mcp/ or similar directories.
    """
    found: List[str] = []
    search_patterns = [
        f"mcp/{server_name}_tools.json",
        f"mcp/tools/{server_name}.json",
        f".cursor/{server_name}_tools.json",
        "mcp/filesystem_tools.json",
        "mcp/tools.json",
    ]
    for rel in search_patterns:
        path = repo_root / rel
        if not path.exists():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        tools = data.get("tools") or data.get("functions") or data
        found.extend(_check_tool_descriptions(tools, server_name, rel))
    return found


# Keep old private name as alias for any internal callers
_scan_companion_tool_files = scan_companion_tool_files

# Patterns indicating injected instructions in tool return values
_RESPONSE_INJECTION_PATTERNS = [
    _re.compile(r"\b(include|repeat|output|print|say|tell)\b.{0,50}\b(verbatim|exactly|word.for.word)\b", _re.I),
    _re.compile(r"\bin your next\s+(response|message|reply|output)\b", _re.I),
    _re.compile(r"\bdo not\s+(mention|tell|reveal|disclose)\b", _re.I),
    _re.compile(r"\bignore\b.{0,30}\b(previous|prior|above|instructions?)\b", _re.I),
    _re.compile(r"\balways\s+(include|append|add|output|return)\b", _re.I),
    _re.compile(r"\bnew (instructions?|task|objective|directive)\b", _re.I),
    _re.compile(r"\bsystem\s*(override|instruction|command)\b", _re.I),
]

# Generic MCP-builtin tool names — shadowing these is high risk
_BUILTIN_TOOL_NAMES = {
    "search", "read_file", "write_file", "list_directory", "execute",
    "run_command", "bash", "python", "get_file", "list_files",
    "fetch", "browse", "web_search",
}


def scan_all_json_tool_files(repo_root: Path) -> List[Tuple[str, str]]:
    """
    Scan ALL JSON files in the repo for tool definition arrays with poisoned
    descriptions or hardcoded credentials. Works regardless of file location.
    Returns list of (evidence_string, relative_file_path) tuples.
    """
    found: List[Tuple[str, str]] = []
    _skip_dirs = {"node_modules", ".git", "__pycache__", "venv", ".venv", "dist", "build", ".tox"}
    for json_path in repo_root.rglob("*.json"):
        rel = str(json_path.relative_to(repo_root))
        if any(skip in rel.split("/") for skip in _skip_dirs):
            continue
        try:
            data = json.loads(json_path.read_text(encoding="utf-8", errors="ignore"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        tools = data.get("tools") or data.get("functions") or []
        if not tools:
            continue
        server_label = json_path.stem
        evidence_list = _check_tool_descriptions(tools, server_label, rel)
        for ev in evidence_list:
            found.append((ev, rel))
        # Also check for hardcoded credentials in env blocks at top level
        env = data.get("env") or {}
        cred_ev = _check_env_for_credentials(env, server_label, rel)
        for ev in cred_ev:
            found.append((ev, rel))
    return found


def scan_python_mcp_server_file(py_path: Path) -> Tuple[List[str], List[str]]:
    """
    Parse a Python file that implements an MCP server.
    Returns (tool_names, injection_evidence).
    tool_names: names extracted from list_tools() return values.
    injection_evidence: evidence strings if tool handlers inject instructions.
    """
    tool_names: List[str] = []
    injection_evidence: List[str] = []
    try:
        source = py_path.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(source)
    except Exception:
        return tool_names, injection_evidence

    handler_names = {"call_tool", "handle_tool_call", "dispatch_tool"}

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        # Extract tool names from list_tools()
        if node.name == "list_tools":
            for sub in ast.walk(node):
                if isinstance(sub, ast.Dict):
                    for i, k in enumerate(sub.keys):
                        if isinstance(k, ast.Constant) and k.value == "name":
                            v = sub.values[i]
                            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                                tool_names.append(v.value)

        # Check tool handler methods for response injection
        is_handler = (
            node.name in handler_names
            or node.name.startswith("_handle_")
            or node.name.startswith("handle_")
        )
        if is_handler:
            for sub in ast.walk(node):
                if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                    val = sub.value
                    if len(val) < 10:
                        continue
                    for pat in _RESPONSE_INJECTION_PATTERNS:
                        if pat.search(val):
                            lineno = getattr(sub, "lineno", "?")
                            injection_evidence.append(
                                f"RESPONSE INJECTION at line {lineno} in "
                                f"{node.name}(): {val[:100]!r}"
                            )
                            break

    return tool_names, injection_evidence


def scan_tool_descriptions(cfg: Dict[str, Any]) -> List[str]:
    """Return a list of suspicious tool names from a single MCP server config dict."""
    tools = cfg.get("tools") or cfg.get("functions") or []
    suspicious: List[str] = []
    items = tools.values() if isinstance(tools, dict) else tools
    for tool in items:
        if not isinstance(tool, dict):
            continue
        name = tool.get("name", "")
        desc = tool.get("description", "")
        flagged = name.lower() in DANGEROUS_TOOL_NAMES
        if not flagged:
            for pat in SUSPICIOUS_DESCRIPTION_PATTERNS:
                if pat.search(desc):
                    flagged = True
                    break
        if flagged and name:
            suspicious.append(name)
    return suspicious


def detect_mcp(repo_root: Path) -> DetectionResult:
    """
    Detect MCP servers from config files.
    Also scans for:
    - Poisoned tool descriptions (prompt injection via tool metadata)
    - Hardcoded credentials in env blocks
    - Dangerous tool names (shell, exec, run_command)
    - Companion tool definition files
    - Tool shadowing across servers
    """
    repo_root = repo_root.resolve()
    evidence: List[str] = []
    servers: List[Dict[str, Any]] = []
    security_findings: List[str] = []

    # Track tool names across all servers to detect shadowing
    all_tool_names: Dict[str, str] = {}  # tool_name -> first_server

    for rel_path in MCP_CONFIG_PATHS:
        config_path = repo_root / rel_path
        if not config_path.exists():
            continue
        try:
            raw = config_path.read_text(encoding="utf-8")
            config = json.loads(raw)
        except (OSError, json.JSONDecodeError):
            continue

        cfg_servers = config.get("mcpServers") or config.get("mcp_servers") or {}
        for name, cfg in cfg_servers.items():
            if not isinstance(cfg, dict):
                continue

            evidence.append(f"MCP: {name} ({rel_path})")
            server_entry: Dict[str, Any] = {
                "name": name,
                "config_path": rel_path,
                "trust_score": 100,
                "suspicious_description": False,
                "suspicious_tools": [],
            }

            # Check args for dangerous filesystem access
            args = cfg.get("args", [])
            if isinstance(args, list):
                for arg in args:
                    if isinstance(arg, str) and arg in ("/", "~", str(Path.home())):
                        finding = (
                            f"EXCESSIVE PERMISSIONS: {name} allowed-dirs={arg!r} "
                            f"gives access to entire filesystem ({rel_path})"
                        )
                        security_findings.append(finding)
                        server_entry["trust_score"] -= 40

            # Check env block for hardcoded credentials
            env = cfg.get("env", {})
            cred_findings = _check_env_for_credentials(env, name, rel_path)
            security_findings.extend(cred_findings)
            if cred_findings:
                server_entry["trust_score"] -= 30

            # Check inline tool definitions
            tools = cfg.get("tools") or cfg.get("functions") or []
            tool_findings = _check_tool_descriptions(tools, name, rel_path)
            security_findings.extend(tool_findings)
            if tool_findings:
                server_entry["suspicious_description"] = True
                server_entry["suspicious_tools"] = [
                    f.split(":")[1].strip() for f in tool_findings
                ]
                server_entry["trust_score"] -= 50

            # Check companion tool files on disk
            companion_findings = _scan_companion_tool_files(repo_root, name)
            security_findings.extend(companion_findings)
            if companion_findings:
                server_entry["suspicious_description"] = True
                server_entry["trust_score"] -= 50

            # Tool shadowing check
            for tool in (tools if isinstance(tools, list) else []):
                if isinstance(tool, dict):
                    tname = tool.get("name", "")
                    if tname:
                        if tname in all_tool_names:
                            security_findings.append(
                                f"TOOL SHADOWING: tool '{tname}' registered by both "
                                f"'{all_tool_names[tname]}' and '{name}' — "
                                f"agent may call wrong server ({rel_path})"
                            )
                            server_entry["trust_score"] -= 25
                        else:
                            all_tool_names[tname] = name

            # Raw JSON credential pattern check (catches inline env values)
            if CREDENTIAL_KEY_PATTERNS.search(raw):
                server_entry["trust_score"] = min(server_entry["trust_score"], 60)

            servers.append(server_entry)

    # Add security findings to evidence
    evidence.extend(security_findings[:15])

    if not servers:
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
        evidence=evidence[:20],
        details={
            "detected": True,
            "servers": servers,
            "security_findings": security_findings,
            "has_poisoned_tools": any(s.get("suspicious_description") for s in servers),
            "has_hardcoded_creds": any(
                "HARDCODED CREDENTIAL" in f for f in security_findings
            ),
            "has_excessive_permissions": any(
                "EXCESSIVE PERMISSIONS" in f for f in security_findings
            ),
        },
    )
