"""
Generate a Mermaid.js diagram showing relationships between AI components.

Shows: Application -> AI/Cloud SDKs -> External APIs / Local Models
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from ..models import AIBOM, Component, ComponentType

if TYPE_CHECKING:
    from ..architecture_inference import ArchitectureResult

# Component categories for diagram layout (only these appear in the AI diagram)
AI_API_SDKS = {"openai", "anthropic", "cohere", "google-generativeai", "vertexai", "mistralai", "litellm"}
LOCAL_ML = {"transformers", "accelerate", "diffusers", "vllm"}
CLOUD = {"boto3", "google-cloud", "google-cloud-aiplatform", "azure-ai", "azure-core", "azure-identity"}
AI_ORCHESTRATION = {"langchain", "langchain-community", "llama-index", "litellm"}
AGENT_FRAMEWORKS = {"langgraph", "crewai", "autogen", "semantic-kernel", "semantic_kernel", "haystack"}
ALL_AI_CLOUD = AI_API_SDKS | LOCAL_ML | CLOUD | AI_ORCHESTRATION


def _sanitize_id(name: str) -> str:
    """Make a string safe for Mermaid node ids (alphanumeric and underscore only)."""
    if name is None:
        return "unknown"
    safe = name.replace(".", "_").replace("-", "_").replace(" ", "_").replace("/", "_")
    return "".join(c if c.isalnum() or c == "_" else "_" for c in safe)


def _quote_label(label: str) -> str:
    """Escape label for Mermaid - wrap in quotes to handle special chars like ()[]@/"""
    if label is None:
        label = ""
    escaped = label.replace('"', "&quot;")
    return f'"{escaped}"'


def to_ai_component_mermaid(aibom: AIBOM, architecture_result: Optional["ArchitectureResult"] = None) -> str:
    """
    Generate a Mermaid flowchart showing links between AI components,
    models, and external services. Includes inferred architecture type when provided.
    """
    lines: list[str] = ["flowchart TB"]
    if architecture_result and architecture_result.architecture_types != ["Unknown"]:
        arch_label = " + ".join(architecture_result.architecture_types)
        lines.append(f"    subgraph inferred[\"Inferred: {arch_label}\"]")
        for c in architecture_result.components[:6]:
            nid = "inf_" + _sanitize_id(c)
            lines.append(f"        {nid}[\"{c}\"]")
        lines.append("    end")
    lines.append("    subgraph app[Application]")
    lines.append("        repo[Repository]")
    lines.append("    end")

    ai_components: list[Component] = []
    cloud_components: list[Component] = []
    other_components: list[Component] = []

    for c in aibom.components:
        if c.name is None:
            continue
        name_lower = c.name.lower()
        if name_lower in AI_API_SDKS or name_lower in LOCAL_ML or name_lower in AI_ORCHESTRATION:
            ai_components.append(c)
        elif name_lower in AGENT_FRAMEWORKS:
            ai_components.append(c)  # Agent frameworks go in AI section
        elif c.properties.get("aitrace:mcp_server"):
            ai_components.append(c)  # MCP server packages
        elif name_lower in CLOUD or "azure" in name_lower or "google" in name_lower or "boto" in name_lower:
            cloud_components.append(c)
        elif c.type == ComponentType.MODEL:
            other_components.append(c)

    # Add MCP servers from config (not in components)
    mcp_servers = getattr(aibom, "mcp_servers", []) or []

    # AI SDK subgraph (includes model config components, agents, MCP)
    if ai_components or aibom.models or other_components or mcp_servers:
        lines.append("")
        lines.append('    subgraph ai["AI & ML Components"]')
        for c in ai_components + other_components:
            nid = _sanitize_id(c.name)
            label = f"{c.name}@{c.version}" if c.version else c.name
            lines.append(f"        {nid}[{_quote_label(label)}]")
        for m in aibom.models:
            mid = _sanitize_id(m.id)
            label = f"{m.name} ({m.format})" if m.format else m.name
            lines.append(f"        {mid}[{_quote_label(label)}]")
        for m in mcp_servers:
            mid = _sanitize_id(m.id)
            label = f"MCP: {m.name}"
            lines.append(f"        {mid}[{_quote_label(label)}]")
        lines.append("    end")

    # Cloud subgraph
    if cloud_components:
        lines.append("")
        lines.append('    subgraph cloud["Cloud Services"]')
        for c in cloud_components:
            nid = _sanitize_id(c.name)
            label = f"{c.name}@{c.version}" if c.version else c.name
            lines.append(f"        {nid}[{_quote_label(label)}]")
        lines.append("    end")

    # External APIs (implicit) - map SDK name to API node
    api_map = {
        "openai": "OpenAI API", "anthropic": "Anthropic API", "cohere": "Cohere API",
        "google-generativeai": "Google AI API", "vertexai": "Vertex AI",
        "mistralai": "Mistral API", "litellm": "Unified API",
    }
    api_sdks_present = [c for c in ai_components if c.name.lower() in AI_API_SDKS]
    if api_sdks_present:
        lines.append("")
        lines.append('    subgraph external["External APIs"]')
        seen_apis = set()
        for c in api_sdks_present:
            api_label = api_map.get(c.name.lower(), f"{c.name} API")
            if api_label not in seen_apis:
                seen_apis.add(api_label)
                nid = _sanitize_id(api_label)
                lines.append(f"        {nid}[{_quote_label(api_label)}]")
        lines.append("    end")

    # Edges: App -> SDKs, model configs, and MCP servers
    lines.append("")
    for c in ai_components + cloud_components + other_components:
        nid = _sanitize_id(c.name)
        lines.append(f"    repo --> {nid}")
    for m in mcp_servers:
        mid = _sanitize_id(m.id)
        lines.append(f"    repo -.->|config| {mid}")

    # Edges: API SDKs -> External APIs
    for c in api_sdks_present:
        api_label = api_map.get(c.name.lower(), f"{c.name} API")
        api_nid = _sanitize_id(api_label)
        nid = _sanitize_id(c.name)
        lines.append(f"    {nid} --> {api_nid}")

    # Edges: Local ML SDKs -> Models
    for c in ai_components:
        name_lower = c.name.lower()
        if name_lower in LOCAL_ML and aibom.models:
            nid = _sanitize_id(c.name)
            for m in aibom.models[:5]:  # Limit to avoid clutter
                mid = _sanitize_id(m.id)
                lines.append(f"    {nid} -.->|loads| {mid}")

    # Edges: Repo -> Models (when models exist but no local ML SDK)
    if aibom.models and not any(c.name.lower() in LOCAL_ML for c in ai_components):
        for m in aibom.models[:5]:
            mid = _sanitize_id(m.id)
            lines.append(f"    repo -.->|contains| {mid}")

    return "\n".join(lines)
