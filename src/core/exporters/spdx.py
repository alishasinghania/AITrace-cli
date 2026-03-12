"""
SPDX 3.0 AI BOM exporter.

Produces a rich SPDX document with the same AI component coverage as CycloneDX:
- Root package (repo) with metadata
- AI libraries with detection evidence
- Machine-learning-model Artifacts (API models, HuggingFace, binary artifacts)
- Framework components
- Relationships (DESCRIBES, DEPENDS_ON)
"""

from __future__ import annotations

import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, Tuple

from ..models import AIBOM, Finding

if TYPE_CHECKING:
    from ..architecture_inference import ArchitectureResult
    from ..model_supply_chain_analyzer import ModelSupplyChainResult

# Reuse builders from CycloneDX
from .cyclonedx import (
    _build_api_model_components as _cdx_api_models,
    _build_binary_model_components as _cdx_binary_models,
    _build_framework_components as _cdx_frameworks,
    _build_hf_model_components as _cdx_hf_models,
    _build_library_components as _cdx_libraries,
    _build_mcp_components as _cdx_mcp,
    _build_transformers_lib as _cdx_transformers,
    _get_repo_metadata,
)


def _spdx_id(prefix: str = "SPDXRef") -> str:
    """Generate a unique SPDX identifier."""
    return f"{prefix}-{secrets.token_hex(6)}"


def _cdx_to_spdx_package(cdx: Dict[str, Any], spdx_id: str) -> Dict[str, Any]:
    """Convert CycloneDX library/component dict to SPDX 3.0 Package element."""
    elem: Dict[str, Any] = {
        "@id": spdx_id,
        "type": "Package",
        "name": cdx.get("name", ""),
        "description": cdx.get("description", ""),
        "versionInfo": cdx.get("version", "detected"),
    }
    purl = cdx.get("purl")
    if purl:
        elem["externalIdentifier"] = [{"type": "purl", "identifier": purl}]
    # Evidence and detection metadata in annotation/extension
    props = cdx.get("properties", [])
    if props:
        elem["comment"] = " | ".join(
            f"{p.get('name', '')}: {p.get('value', '')}" for p in props[:6]
        )
    return elem


def _cdx_to_spdx_artifact(cdx: Dict[str, Any], spdx_id: str) -> Dict[str, Any]:
    """Convert CycloneDX machine-learning-model dict to SPDX 3.0 Artifact element."""
    elem: Dict[str, Any] = {
        "@id": spdx_id,
        "type": "Artifact",
        "name": cdx.get("name", ""),
        "description": cdx.get("description", ""),
    }
    purl = cdx.get("purl")
    if purl:
        elem["externalIdentifier"] = [{"type": "purl", "identifier": purl}]
    author = cdx.get("author")
    if author:
        elem["originatedBy"] = [{"type": "Person", "name": author}]
    # Include SHA256 hash when present (from ModelArtifact.config)
    hashes = cdx.get("hashes", [])
    if hashes:
        elem["hashes"] = hashes
    # Evidence in comment
    props = cdx.get("properties", [])
    ev_parts = [f"{p.get('name')}: {p.get('value')}" for p in props if "evidence" in str(p.get("name", "")).lower()]
    if ev_parts:
        elem["comment"] = " | ".join(ev_parts[:4])
    # Include model sha256 when present (from CycloneDX hashes)
    hashes = cdx.get("hashes", [])
    for h in hashes:
        if h.get("alg") == "SHA-256" and h.get("content"):
            elem["contentIdentifier"] = f"sha256:{h['content']}"
            break
    return elem


def _cdx_to_spdx_service(cdx: Dict[str, Any], spdx_id: str) -> Dict[str, Any]:
    """Convert CycloneDX service dict to SPDX element."""
    return {
        "@id": spdx_id,
        "type": "Package",
        "name": cdx.get("name", ""),
        "description": cdx.get("description", ""),
        "comment": "MCP server",
    }


def to_spdx_json(
    aibom: AIBOM,
    architecture_result: Optional["ArchitectureResult"] = None,
    findings: Optional[List[Finding]] = None,
    llm_usage: Optional[Dict[str, Any]] = None,
    model_supply_chain: Optional["ModelSupplyChainResult"] = None,
) -> Dict[str, Any]:
    """
    Serialize AIBOM to a rich SPDX 3.0-style JSON document.

    Includes:
    - Root package (repo) with metadata
    - AI libraries with evidence
    - Machine-learning-model Artifacts (API, HuggingFace, binaries)
    - Framework components
    - Relationships (DESCRIBES, DEPENDS_ON)
    """
    from ..detectors.config_reference_detector import detect_model_references

    repo_path = aibom.repo_path
    findings = findings or []
    now = datetime.now(timezone.utc).isoformat()
    creation_info = {"created": now, "creators": ["Tool: AITrace CLI"]}

    # Repo metadata
    repo_meta = _get_repo_metadata(repo_path)
    grp = (repo_meta["group"] or "").replace("/", "-").replace(" ", "-")
    nm = (repo_meta["name"] or "repo").replace("/", "-").replace(" ", "-")
    root_id = f"SPDXRef-repo-{grp}-{nm}" if grp else f"SPDXRef-repo-{nm}"

    # Build CycloneDX-style components (we reuse the builders)
    model_refs = detect_model_references(repo_path)

    lib_comps, lib_refs = _cdx_libraries(aibom, findings, llm_usage)
    api_models, api_refs = _cdx_api_models(model_refs, repo_path)
    hf_models, hf_refs = _cdx_hf_models(model_supply_chain, repo_path)
    bin_models, bin_refs = _cdx_binary_models(aibom)
    fw_comps, fw_refs = _cdx_frameworks(architecture_result)
    mcp_comps, mcp_refs = _cdx_mcp(aibom)
    transformers_comp, tf_ref = _cdx_transformers(aibom)

    # Map bom-ref -> SPDX ID
    id_map: Dict[str, str] = {}
    elements: List[Dict[str, Any]] = []
    relationships: List[Dict[str, str]] = []

    # Root package
    root_elem: Dict[str, Any] = {
        "@id": root_id,
        "type": "Package",
        "name": repo_meta["name"],
        "description": repo_meta["description"],
        "versionInfo": repo_meta["version"],
        "externalIdentifier": [{"type": "purl", "identifier": repo_meta["purl"]}],
    }
    if "github" in repo_meta["purl"]:
        root_elem["externalRef"] = [
            {"type": "vcs", "locator": repo_meta["purl"].replace("pkg:github/", "https://github.com/")},
        ]
    elements.append(root_elem)

    def add_element(cdx: Dict[str, Any], elem_type: str = "Package") -> str:
        bom_ref = cdx.get("bom-ref", "")
        spdx_id = id_map.get(bom_ref)
        if spdx_id:
            return spdx_id
        spdx_id = f"SPDXRef-{bom_ref}" if bom_ref else _spdx_id("SPDXRef")
        id_map[bom_ref] = spdx_id
        if cdx.get("type") == "machine-learning-model":
            elem = _cdx_to_spdx_artifact(cdx, spdx_id)
        elif cdx.get("type") == "service":
            elem = _cdx_to_spdx_service(cdx, spdx_id)
        else:
            elem = _cdx_to_spdx_package(cdx, spdx_id)
        elements.append(elem)
        return spdx_id

    all_dep_ids: List[str] = []

    for c in lib_comps:
        sid = add_element(c)
        all_dep_ids.append(sid)
    for c in api_models + hf_models + bin_models:
        sid = add_element(c)
        all_dep_ids.append(sid)
    for c in fw_comps:
        sid = add_element(c)
        all_dep_ids.append(sid)
    for c in mcp_comps:
        sid = add_element(c)
        all_dep_ids.append(sid)

    tf_id: Optional[str] = None
    if transformers_comp:
        tf_id = add_element(transformers_comp)
        all_dep_ids.append(tf_id)

    # Relationships: root DESCRIBES / DEPENDS_ON all
    for dep_id in all_dep_ids:
        if dep_id != root_id:
            relationships.append({
                "from": root_id,
                "to": dep_id,
                "relationshipType": "DEPENDS_ON",
            })

    # Models -> transformers where applicable
    if tf_id:
        for cdx in api_models + hf_models + bin_models:
            author = (cdx.get("author") or "").lower()
            if "huggingface" in author or "local" in author or "meta" in author:
                bom_ref = cdx.get("bom-ref")
                if bom_ref and bom_ref in id_map:
                    relationships.append({
                        "from": id_map[bom_ref],
                        "to": tf_id,
                        "relationshipType": "DEPENDS_ON",
                    })

    # Document element (SPDX 3.0 root)
    doc_id = "SPDXRef-DOCUMENT"
    elements.insert(0, {
        "@id": doc_id,
        "type": "SpdxDocument",
        "name": "AITrace AI BOM",
        "creationInfo": creation_info,
        "element": root_id,
    })
    relationships.insert(0, {
        "from": doc_id,
        "to": root_id,
        "relationshipType": "DESCRIBES",
    })

    doc: Dict[str, Any] = {
        "spdxVersion": "SPDX-3.0",
        "creationInfo": creation_info,
        "elements": elements,
        "relationships": relationships,
    }
    if architecture_result:
        doc["aitrace"] = {
            "architecture": architecture_result.to_dict(),
        }
    agent_tools = getattr(aibom, "agent_tools", None) or []
    if agent_tools:
        doc.setdefault("aitrace", {})["agent_tools"] = agent_tools
    return doc
