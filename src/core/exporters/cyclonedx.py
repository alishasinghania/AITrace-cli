"""
CycloneDX 1.7 AI BOM exporter.

Produces a rich SBOM with:
- Root component metadata (repo)
- Tools metadata (AITrace)
- AI libraries with detection evidence
- Machine-learning-model entries (API models, HuggingFace models, binary artifacts)
- Framework/technique components
- Dependencies graph
"""

from __future__ import annotations

import json
import re
import secrets
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, Tuple

from ..models import AIBOM, Component, ComponentType, Finding, MCPServer, ModelArtifact, Severity

if TYPE_CHECKING:
    from ..architecture_inference import ArchitectureResult
    from ..model_supply_chain_analyzer import ModelSupplyChainResult

# AI/LLM providers that are libraries (for "Usage Detected" naming)
AI_LIBRARY_PROVIDERS = frozenset({
    "openai", "anthropic", "cohere", "vertexai", "google-generativeai", "mistralai",
    "litellm", "replicate", "together", "fireworks", "fireworks-ai", "groq", "ollama",
    "ai21", "aleph-alpha-client", "aleph_alpha", "perplexity",
})

# Provider -> display author for machine-learning-model
PROVIDER_AUTHOR: Dict[str, str] = {
    "openai": "OpenAI",
    "anthropic": "Anthropic",
    "cohere": "Cohere",
    "google-generativeai": "Google",
    "vertexai": "Google",
    "mistralai": "Mistral",
    "ollama": "Ollama",
    "huggingface": "HuggingFace",
    "meta": "Meta",
    "meta-ai": "Meta",
}


def _get_repo_metadata(repo_path: Path) -> Dict[str, Any]:
    """Extract repo name, group, version, description from pyproject.toml or package.json."""
    repo_path = Path(repo_path).resolve()
    name = repo_path.name
    group = ""
    version = "main"
    description = ""

    # pyproject.toml
    pyproject = repo_path / "pyproject.toml"
    if pyproject.exists():
        try:
            content = pyproject.read_text(encoding="utf-8", errors="ignore")
            m = re.search(r'\[project\]\s*\n.*?name\s*=\s*["\']([^"\']+)["\']', content, re.DOTALL)
            if m:
                name = m.group(1)
            m = re.search(r'version\s*=\s*["\']([^"\']+)["\']', content)
            if m:
                version = m.group(1)
            m = re.search(r'description\s*=\s*["\']([^"\']+)["\']', content)
            if m:
                description = m.group(1)
        except OSError:
            pass

    # package.json
    pkg_json = repo_path / "package.json"
    if pkg_json.exists():
        try:
            data = json.loads(pkg_json.read_text(encoding="utf-8"))
            if "name" in data:
                name = data["name"]
            if "version" in data:
                version = data["version"]
            if "description" in data:
                description = data.get("description", "") or description
        except (OSError, json.JSONDecodeError):
            pass

    # GitHub-style group from path (e.g. org/repo)
    if "/" in str(repo_path) and "github" in str(repo_path).lower():
        parts = str(repo_path).split("/")
        if len(parts) >= 2:
            group = parts[-2].lower()
    else:
        group = name.split("/")[0].lower() if "/" in name else ""

    if group and "/" not in name:
        purl = f"pkg:github/{group}/{name}"
    else:
        purl = f"pkg:generic/{name.replace('/', '-')}"

    return {
        "name": name.split("/")[-1] if "/" in name else name,
        "group": group or name.split("/")[0] if "/" in name else "",
        "version": version,
        "description": description or f"Repository: {name}",
        "purl": purl,
    }


def _read_line_snippet(repo_path: Path, file_path: str, line: Optional[int]) -> Optional[str]:
    """Read a single line from file for evidence snippet."""
    if not line or not file_path:
        return None
    try:
        path = repo_path / file_path
        if not path.exists():
            return None
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        if 1 <= line <= len(lines):
            return lines[line - 1].strip()[:200]
    except (OSError, UnicodeDecodeError):
        pass
    return None


def _generate_bom_ref(prefix: str) -> str:
    """Generate a unique bom-ref."""
    return f"{prefix}-{secrets.token_hex(6)}"


def _build_library_components(
    aibom: AIBOM,
    findings: List[Finding],
    llm_usage: Optional[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], Set[str]]:
    """Build library components with evidence. Returns (components, bom_refs)."""
    components: List[Dict[str, Any]] = []
    refs: Set[str] = set()

    # Index findings by component_id and by component name (for inferred)
    findings_by_comp: Dict[str, List[Finding]] = {}
    for f in findings:
        cid = f.component_id or ""
        if cid:
            findings_by_comp.setdefault(cid, []).append(f)
        # Also match by purl/name for inferred components
        for c in aibom.components:
            if c.id == cid or (f.title and c.name and c.name.lower() in f.title.lower()):
                findings_by_comp.setdefault(c.id, []).append(f)
                break

    comp_by_name: Dict[str, Component] = {}
    for c in aibom.components:
        k = (c.name or "").lower().replace("-", "_")
        comp_by_name[k] = c
        comp_by_name[(c.name or "").lower()] = c

    for c in aibom.components:
        if c.type != ComponentType.LIBRARY:
            continue
        name_lower = (c.name or "").lower()
        if name_lower not in AI_LIBRARY_PROVIDERS and name_lower.replace("-", "_") not in AI_LIBRARY_PROVIDERS:
            continue

        bom_ref = _generate_bom_ref("component")
        refs.add(bom_ref)

        # Evidence from findings
        evidence_locations: List[str] = []
        evidence_snippets: List[str] = []
        comp_findings = findings_by_comp.get(c.id, [])
        for f in comp_findings:
            for ev in f.evidence[:3]:
                loc = ev.file or "unknown"
                if ev.line:
                    loc = f"{loc}:{ev.line}"
                evidence_locations.append(loc)
                snippet = ev.description
                if ev.file and ev.line and aibom.repo_path:
                    sn = _read_line_snippet(aibom.repo_path, ev.file, ev.line)
                    if sn:
                        snippet = sn
                evidence_snippets.append(snippet or ev.description)

        # Evidence from llm_usage (provider in pattern)
        if llm_usage and not evidence_locations:
            for pattern, usage in llm_usage.items():
                pat_lower = pattern.lower().split(".")[0] if "." in pattern else pattern.lower()
                if name_lower in pat_lower or name_lower.replace("-", "_") in pat_lower:
                    for fp in (usage.files if hasattr(usage, "files") else usage.get("files", []))[:3]:
                        evidence_locations.append(fp)
                        evidence_snippets.append(pattern)

        # Fallback: manifest
        if not evidence_locations:
            evidence_locations.append("Dependency manifest")
            evidence_snippets.append(f"SPDX Package: {c.name}@{c.version or 'unknown'}")

        is_usage = bool(comp_findings) or bool(llm_usage)
        display_name = f"{c.name} - Usage Detected" if is_usage else f"Dependency: {c.name}"
        desc = f"{c.name} (unknown) is installed and used in code" if is_usage else f"LLM-related dependency: {c.name} (version: unknown)"

        props: List[Dict[str, str]] = [
            {"name": "cdx:detection:category", "value": "dependencies"},
            {"name": "cdx:detection:severity", "value": "high"},
            {"name": "cdx:detection:weight", "value": "5"},
        ]
        for i, (loc, snip) in enumerate(zip(evidence_locations[:5], evidence_snippets[:5])):
            props.append({"name": f"cdx:evidence:location:{i}", "value": loc})
            props.append({"name": f"cdx:evidence:snippet:{i}", "value": snip[:500] if snip else ""})

        comp_dict: Dict[str, Any] = {
            "type": "library",
            "bom-ref": bom_ref,
            "name": display_name,
            "version": "detected",
            "description": desc,
            "scope": "required",
            "properties": props,
        }
        if c.purl or c.id.startswith("pkg:"):
            comp_dict["purl"] = c.purl or c.id
        components.append(comp_dict)

    return components, refs


def _build_api_model_components(
    model_refs: List[Tuple[str, str, str, Optional[int]]],
    repo_path: Path,
) -> Tuple[List[Dict[str, Any]], Set[str]]:
    """Build machine-learning-model for API models (gpt-4o, claude-3-opus, etc)."""
    components: List[Dict[str, Any]] = []
    refs: Set[str] = set()

    seen: Set[Tuple[str, str]] = set()
    for provider, model_id, file_path, line in model_refs:
        key = (provider.lower(), model_id.lower())
        if key in seen:
            continue
        seen.add(key)

        bom_ref = _generate_bom_ref("model")
        refs.add(bom_ref)

        author = PROVIDER_AUTHOR.get(provider.lower(), provider)
        props: List[Dict[str, str]] = [
            {"name": "category", "value": "text-generation"},
            {"name": "intended-use", "value": "Text generation, chat completion, and language understanding"},
            {"name": "cdx:detection:method", "value": "automated-code-analysis"},
            {"name": "cdx:detection:confidence", "value": "high"},
            {"name": "cdx:detection:weight", "value": "5"},
        ]
        snippet = _read_line_snippet(repo_path, file_path, line)
        props.append({"name": "evidence:location:1", "value": f"{file_path}:{line}" if line else file_path})
        props.append({"name": "evidence:snippet:1", "value": snippet or model_id})

        purl = f"pkg:ml/{provider.lower().replace('-', '/')}/{model_id}"
        ext_refs: List[Dict[str, str]] = []
        if "openai" in provider.lower():
            ext_refs.append({"comment": "API Documentation", "type": "documentation", "url": "https://platform.openai.com/docs/models"})
        elif "anthropic" in provider.lower():
            ext_refs.append({"comment": "Model Documentation", "type": "documentation", "url": "https://docs.anthropic.com/claude/docs/models-overview"})
        elif "google" in provider.lower() or "generativeai" in provider.lower():
            ext_refs.append({"comment": "Model Documentation", "type": "documentation", "url": "https://ai.google.dev/models"})

        comp_dict: Dict[str, Any] = {
            "type": "machine-learning-model",
            "bom-ref": bom_ref,
            "author": author,
            "name": model_id,
            "version": "latest",
            "description": f"{author} model: {model_id} (text-generation)",
            "scope": "required",
            "properties": props,
            "purl": purl,
            "externalReferences": ext_refs,
            "modelCard": {
                "modelParameters": {
                    "tasks": [{"task": "text-generation"}],
                    "inputs": [{"format": "text"}],
                    "outputs": [{"format": "text"}],
                },
                "considerations": {},
            },
        }
        components.append(comp_dict)

    return components, refs


def _build_hf_model_components(
    model_supply_chain: Optional["ModelSupplyChainResult"],
    repo_path: Path,
) -> Tuple[List[Dict[str, Any]], Set[str]]:
    """Build machine-learning-model for HuggingFace models."""
    components: List[Dict[str, Any]] = []
    refs: Set[str] = set()
    if not model_supply_chain:
        return components, refs

    for agg in model_supply_chain.aggregated_models:
        model_id = agg.model
        bom_ref = _generate_bom_ref("model")
        refs.add(bom_ref)

        org = model_id.split("/")[0] if "/" in model_id else "HuggingFace"
        author = PROVIDER_AUTHOR.get(org.lower(), org)

        props: List[Dict[str, str]] = [
            {"name": "cdx:detection:method", "value": "automated-code-analysis"},
            {"name": "cdx:detection:confidence", "value": "high"},
            {"name": "cdx:detection:weight", "value": "5"},
        ]
        for i, floc in enumerate(agg.files[:3], 1):
            parts = floc.split(":")
            fp, ln = parts[0], int(parts[1]) if len(parts) > 1 else None
            props.append({"name": f"evidence:location:{i}", "value": floc})
            snip = _read_line_snippet(repo_path, fp, ln)
            props.append({"name": f"evidence:snippet:{i}", "value": snip or model_id})

        comp_dict: Dict[str, Any] = {
            "type": "machine-learning-model",
            "bom-ref": bom_ref,
            "author": author,
            "name": model_id.replace("/", "_"),
            "version": "latest",
            "description": f"HuggingFace model: {model_id}",
            "scope": "required",
            "properties": props,
            "externalReferences": [
                {"comment": "Model source", "type": "vcs", "url": f"https://huggingface.co/{model_id}"},
            ],
        }
        if "/" in model_id:
            comp_dict["purl"] = f"pkg:ml/huggingface/{model_id}"
        components.append(comp_dict)

    return components, refs


def _build_binary_model_components(aibom: AIBOM) -> Tuple[List[Dict[str, Any]], Set[str]]:
    """Build machine-learning-model or file for binary model artifacts."""
    components: List[Dict[str, Any]] = []
    refs: Set[str] = set()

    for m in aibom.models:
        bom_ref = m.id if m.id.startswith("pkg:") else _generate_bom_ref("model")
        refs.add(bom_ref)

        comp_dict: Dict[str, Any] = {
            "type": "machine-learning-model",
            "bom-ref": bom_ref,
            "author": "Local",
            "name": m.name,
            "version": "latest",
            "description": f"Local model artifact: {m.path} ({m.format or 'unknown'})",
            "scope": "required",
            "properties": [
                {"name": "cdx:detection:method", "value": "file-scan"},
                {"name": "aitrace:path", "value": m.path},
                {"name": "aitrace:format", "value": m.format or "unknown"},
            ],
        }
        if m.size_bytes is not None:
            comp_dict["properties"].append({"name": "aitrace:size_bytes", "value": str(m.size_bytes)})
        if m.config and m.config.get("sha256"):
            comp_dict["hashes"] = [{"alg": "SHA-256", "content": m.config["sha256"]}]
        components.append(comp_dict)

    return components, refs


def _build_framework_components(
    architecture_result: Optional["ArchitectureResult"],
) -> Tuple[List[Dict[str, Any]], Set[str]]:
    """Build framework/technique components from architecture detection."""
    components: List[Dict[str, Any]] = []
    refs: Set[str] = set()
    if not architecture_result:
        return components, refs

    for arch_type in architecture_result.architecture_types:
        bom_ref = _generate_bom_ref("component")
        refs.add(bom_ref)

        evidence = architecture_result.details.get(arch_type, {}).get("evidence", [])[:2]
        props: List[Dict[str, str]] = [
            {"name": "cdx:detection:severity", "value": "info"},
            {"name": "cdx:detection:weight", "value": "4"},
        ]
        for i, ev in enumerate(evidence[:2]):
            props.append({"name": f"cdx:evidence:location:{i}", "value": str(ev)[:200]})
            props.append({"name": f"cdx:evidence:snippet:{i}", "value": str(ev)[:100]})

        cat = "data-pipeline" if "RAG" in arch_type or "Embedding" in arch_type else "framework"
        props.insert(0, {"name": "cdx:detection:category", "value": cat})

        comp_dict: Dict[str, Any] = {
            "type": "framework",
            "bom-ref": bom_ref,
            "name": f"{arch_type} Detected",
            "version": "detected",
            "description": f"Found {arch_type} in {len(evidence)} location(s)",
            "scope": "required",
            "properties": props,
        }
        components.append(comp_dict)

    return components, refs


def _build_mcp_components(aibom: AIBOM) -> Tuple[List[Dict[str, Any]], Set[str]]:
    """Build MCP server components."""
    components: List[Dict[str, Any]] = []
    refs: Set[str] = set()
    for m in getattr(aibom, "mcp_servers", []) or []:
        comp_dict: Dict[str, Any] = {
            "type": "service",
            "bom-ref": m.id,
            "name": m.name,
            "version": "detected",
            "description": f"MCP server from {m.config_path}",
            "scope": "required",
            "properties": [
                {"name": "aitrace:mcp_server", "value": "true"},
                {"name": "aitrace:config_path", "value": m.config_path},
            ],
        }
        if m.package:
            comp_dict["properties"].append({"name": "aitrace:package", "value": m.package})
        components.append(comp_dict)
        refs.add(m.id)
    return components, refs


def _build_transformers_lib(aibom: AIBOM) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Add transformers as a library when HuggingFace models are used."""
    has_hf = any(
        c.name and "transformers" in (c.name or "").lower()
        for c in aibom.components
    ) or any(
        m.path and "transformers" in str(m.path).lower()
        for m in aibom.models
    )
    if not has_hf:
        return None, None
    bom_ref = "lib-transformers"
    return {
        "type": "library",
        "bom-ref": bom_ref,
        "name": "Transformers",
        "description": "State-of-the-art Machine Learning for PyTorch, TensorFlow, and JAX",
        "purl": "pkg:pypi/transformers",
        "externalReferences": [{"type": "website", "url": "https://huggingface.co/docs/transformers"}],
    }, bom_ref


def to_cyclonedx_json(
    aibom: AIBOM,
    architecture_result: Optional["ArchitectureResult"] = None,
    findings: Optional[List[Finding]] = None,
    llm_usage: Optional[Dict[str, Any]] = None,
    model_supply_chain: Optional["ModelSupplyChainResult"] = None,
) -> Dict[str, Any]:
    """
    Serialize AIBOM to a rich CycloneDX 1.7 AI BOM.

    Includes:
    - Root repo metadata
    - Tools metadata (AITrace)
    - AI libraries with evidence
    - machine-learning-model (API models, HuggingFace, binaries)
    - Framework components
    - Dependencies graph
    """
    repo_path = aibom.repo_path
    findings = findings or []
    all_components: List[Dict[str, Any]] = []
    all_refs: Set[str] = set()

    # Repo metadata
    repo_meta = _get_repo_metadata(repo_path)
    grp = (repo_meta["group"] or "").replace("/", "-").replace(" ", "-")
    nm = (repo_meta["name"] or "repo").replace("/", "-").replace(" ", "-")
    root_ref = f"repo-{grp}-{nm}" if grp else f"repo-{nm}"

    # Model references (API models like gpt-4o, claude-3-opus)
    from ..detectors.config_reference_detector import detect_model_references
    model_refs = detect_model_references(repo_path)

    # Build all component types
    lib_comps, lib_refs = _build_library_components(aibom, findings, llm_usage)
    all_components.extend(lib_comps)
    all_refs.update(lib_refs)

    api_models, api_refs = _build_api_model_components(model_refs, repo_path)
    all_components.extend(api_models)
    all_refs.update(api_refs)

    hf_models, hf_refs = _build_hf_model_components(model_supply_chain, repo_path)
    all_components.extend(hf_models)
    all_refs.update(hf_refs)

    bin_models, bin_refs = _build_binary_model_components(aibom)
    all_components.extend(bin_models)
    all_refs.update(bin_refs)

    fw_comps, fw_refs = _build_framework_components(architecture_result)
    all_components.extend(fw_comps)
    all_refs.update(fw_refs)

    mcp_comps, mcp_refs = _build_mcp_components(aibom)
    all_components.extend(mcp_comps)
    all_refs.update(mcp_refs)

    transformers_comp, tf_ref = _build_transformers_lib(aibom)
    if transformers_comp:
        all_components.append(transformers_comp)
        if tf_ref:
            all_refs.add(tf_ref)

    # Dependencies: root -> all
    root_depends = sorted(all_refs)
    dependencies: List[Dict[str, Any]] = [
        {"ref": root_ref, "dependsOn": root_depends},
    ]
    if tf_ref:
        dependencies.append({"ref": tf_ref, "dependsOn": []})
    for ref in all_refs:
        if ref != root_ref and ref != tf_ref:
            deps_for: List[str] = []
            if tf_ref and "model-" in ref:
                comp = next((c for c in all_components if c.get("bom-ref") == ref), None)
                if comp and comp.get("type") == "machine-learning-model":
                    author = (comp.get("author") or "").lower()
                    if "huggingface" in author or "local" in author or "meta" in author:
                        deps_for = [tf_ref]
            dependencies.append({"ref": ref, "dependsOn": deps_for})

    # Metadata
    metadata: Dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tools": {
            "components": [
                {
                    "type": "application",
                    "bom-ref": "tool-aitrace-cli",
                    "name": "AI BOM Generator",
                    "version": "1.0.0",
                    "description": "Automated AI/LLM detection and SBOM generation tool",
                    "externalReferences": [
                        {"type": "website", "url": "https://github.com/cyfinoid/aitrace-cli"},
                    ],
                },
            ],
        },
        "component": {
            "type": "application",
            "bom-ref": root_ref,
            "group": repo_meta["group"],
            "name": repo_meta["name"],
            "version": repo_meta["version"],
            "description": repo_meta["description"],
            "purl": repo_meta["purl"],
            "externalReferences": (
                [
                    {"type": "vcs", "url": repo_meta["purl"].replace("pkg:github/", "https://github.com/")},
                    {"type": "website", "url": repo_meta["purl"].replace("pkg:github/", "https://github.com/")},
                ]
                if "github" in repo_meta["purl"]
                else []
            ),
        },
    }

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "version": 1,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "metadata": metadata,
        "components": all_components,
        "dependencies": dependencies,
    }
