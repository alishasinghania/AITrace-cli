from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from ..models import AIBOM, Component, MCPServer, ModelArtifact

if TYPE_CHECKING:
    from ..architecture_inference import ArchitectureResult


def _component_to_spdx(c: Component) -> Dict[str, Any]:
    """Convert a Component to SPDX element."""
    elem: Dict[str, Any] = {
        "type": "Package",
        "name": c.name,
    }
    purl = c.purl or (c.id if c.id.startswith("pkg:") else None)
    if purl:
        elem["externalIdentifier"] = purl
    if c.version:
        elem["versionInfo"] = c.version
    if c.licenses:
        elem["licenseDeclared"] = c.licenses[0]
    return elem


def _model_to_spdx(m: ModelArtifact) -> Dict[str, Any]:
    """Convert a ModelArtifact to SPDX element (Artifact type for model files)."""
    elem: Dict[str, Any] = {
        "type": "Artifact",
        "name": m.name,
        "SPDXID": m.id,
    }
    if m.path:
        elem["artifactUri"] = m.path
    if m.format:
        elem["artifactFormat"] = m.format
    if m.size_bytes is not None:
        elem["size"] = m.size_bytes
    return elem


def _mcp_to_spdx(m: MCPServer) -> Dict[str, Any]:
    """Convert an MCPServer to SPDX element."""
    elem: Dict[str, Any] = {
        "type": "Service",
        "name": m.name,
        "SPDXID": m.id,
    }
    elem["description"] = f"MCP server from {m.config_path}"
    if m.package:
        elem["externalRefs"] = [{"type": "purl", "locator": f"pkg:npm/{m.package}"}]
    return elem


def to_spdx_json(aibom: AIBOM, architecture_result: Optional["ArchitectureResult"] = None) -> Dict[str, Any]:
    """
    Serialize AIBOM to a minimal SPDX 3.0-style JSON document.
    Includes dependency components, model artifacts, and optional architecture metadata.
    """
    now = datetime.now(timezone.utc).isoformat()
    elements: List[Dict[str, Any]] = []

    for c in aibom.components:
        elements.append(_component_to_spdx(c))
    for m in aibom.models:
        elements.append(_model_to_spdx(m))
    for m in getattr(aibom, "mcp_servers", []) or []:
        elements.append(_mcp_to_spdx(m))

    doc: Dict[str, Any] = {
        "spdxVersion": "SPDX-3.0",
        "creationInfo": {
            "created": now,
            "creators": ["Tool: AITrace CLI"],
        },
        "elements": elements,
    }
    if architecture_result:
        doc["aitrace"] = {
            "architecture": architecture_result.to_dict(),
        }
    agent_tools = getattr(aibom, "agent_tools", None) or []
    if agent_tools:
        doc.setdefault("aitrace", {})["agent_tools"] = agent_tools
    return doc

