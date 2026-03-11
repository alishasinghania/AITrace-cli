from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, Optional

from ..models import AIBOM, Component, ComponentType, MCPServer, ModelArtifact

if TYPE_CHECKING:
    from ..architecture_inference import ArchitectureResult


def _component_to_cyclonedx(c: Component) -> Dict[str, Any]:
    """Convert a Component to CycloneDX format."""
    comp: Dict[str, Any] = {
        "type": c.type.value,
        "name": c.name,
    }
    purl = c.purl or (c.id if c.id.startswith("pkg:") else None)
    if purl:
        comp["purl"] = purl
    if c.version:
        comp["version"] = c.version
    if c.licenses:
        comp["licenses"] = [{"license": {"name": lic}} for lic in c.licenses]
    if c.properties:
        comp["properties"] = [{"name": k, "value": str(v)} for k, v in c.properties.items()]
    return comp


def _model_to_cyclonedx(m: ModelArtifact) -> Dict[str, Any]:
    """Convert a ModelArtifact to CycloneDX component (type=file for binary artifacts)."""
    comp: Dict[str, Any] = {
        "type": "file",
        "name": m.name,
        "bom-ref": m.id,
        "properties": [
            {"name": "aitrace:path", "value": m.path},
            {"name": "aitrace:format", "value": m.format or "unknown"},
        ],
    }
    if m.size_bytes is not None:
        comp["properties"].append({"name": "aitrace:size_bytes", "value": str(m.size_bytes)})
    return comp


def _mcp_to_cyclonedx(m: MCPServer) -> Dict[str, Any]:
    """Convert an MCPServer to CycloneDX component (type=service)."""
    comp: Dict[str, Any] = {
        "type": "service",
        "name": m.name,
        "bom-ref": m.id,
        "properties": [
            {"name": "aitrace:mcp_server", "value": "true"},
            {"name": "aitrace:config_path", "value": m.config_path},
        ],
    }
    if m.package:
        comp["properties"].append({"name": "aitrace:package", "value": m.package})
    return comp


def to_cyclonedx_json(aibom: AIBOM, architecture_result: Optional["ArchitectureResult"] = None) -> Dict[str, Any]:
    """
    Serialize AIBOM to a minimal CycloneDX 1.7-compliant JSON structure.
    Includes dependency components, model artifacts, and optional architecture metadata.
    """
    components: list[Dict[str, Any]] = []
    for c in aibom.components:
        components.append(_component_to_cyclonedx(c))
    for m in aibom.models:
        components.append(_model_to_cyclonedx(m))
    for m in getattr(aibom, "mcp_servers", []) or []:
        components.append(_mcp_to_cyclonedx(m))

    metadata: Dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tools": [
            {
                "vendor": "AITrace",
                "name": "AITrace CLI",
            }
        ],
    }
    if architecture_result:
        props = [{"name": "aitrace:architecture_types", "value": ",".join(architecture_result.architecture_types)}]
        if architecture_result.components:
            props.append({"name": "aitrace:architecture_components", "value": ",".join(architecture_result.components)})
        props.append({"name": "aitrace:architecture_confidence", "value": architecture_result.confidence})
        metadata["properties"] = props

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "version": 1,
        "metadata": metadata,
        "components": components,
    }

