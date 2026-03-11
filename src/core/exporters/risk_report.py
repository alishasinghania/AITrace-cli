from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

from ..models import AIBOM, Finding, FindingCategory, PolicyReport, Severity

if TYPE_CHECKING:
    from ..architecture_detector import ArchitectureResult
from .component_diagram import to_ai_component_mermaid
from .provider_summary import findings_to_detections, summarize_providers

SEVERITY_BADGES = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🟢",
    Severity.INFO: "ℹ️",
}


def _compute_risk_score(findings: List[Finding], n_models: int, policy_passed: bool | None) -> Tuple[int, str]:
    """Return (score 0-100, label). Higher score = higher risk."""
    weights = {Severity.CRITICAL: 25, Severity.HIGH: 15, Severity.MEDIUM: 8, Severity.LOW: 3, Severity.INFO: 1}
    score = sum(weights.get(f.severity, 5) for f in findings)
    score += min(n_models * 5, 20)  # Models add up to 20 points
    if policy_passed is False:
        score += 15
    score = min(score, 100)
    if score >= 70:
        label = "High"
    elif score >= 40:
        label = "Medium"
    elif score >= 15:
        label = "Low"
    else:
        label = "Minimal"
    return score, label


def to_risk_report_json(
    aibom: AIBOM,
    policy: PolicyReport | None,
    findings: List[Finding] | None = None,
    architecture_result: Optional["ArchitectureResult"] = None,
) -> Dict[str, Any]:
    """
    Build an Enterprise Risk Report JSON document.
    """
    findings = findings or []
    risk_score, risk_label = _compute_risk_score(
        findings, len(aibom.models), policy.passed if policy else None
    )
    arch_dict = architecture_result.to_dict() if architecture_result else {"architecture_types": ["Unknown"], "components": [], "confidence": "low"}
    report: Dict[str, Any] = {
        "repo": str(aibom.repo_path),
        "risk_score": {"score": risk_score, "label": risk_label},
        "summary": {
            "component_count": len(aibom.components),
            "model_count": len(aibom.models),
            "dataflow_count": len(aibom.dataflows),
            "finding_count": len(findings),
            "mcp_server_count": len(aibom.mcp_servers),
            "agent_framework_count": len(aibom.agent_frameworks),
        },
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "category": f.category.value,
                "severity": f.severity.value,
                "description": f.description,
                "file": f.evidence[0].file if f.evidence else None,
                "line": f.evidence[0].line if f.evidence else None,
            }
            for f in (findings or [])
            if f.category != FindingCategory.SEMANTIC
        ],
        "architecture": arch_dict,
        "provider_summary": [
            {
                "provider": s.provider,
                "display_name": s.display_name,
                "count": s.count,
                "example_files": s.example_files,
            }
            for s in summarize_providers(findings_to_detections(findings or []))
        ],
        "mcp_servers": [
            {
                "id": m.id,
                "name": m.name,
                "config_path": m.config_path,
                "command": m.command,
                "package": m.package,
            }
            for m in aibom.mcp_servers
        ],
        "agent_frameworks": aibom.agent_frameworks,
        "models": [
            {
                "id": m.id,
                "name": m.name,
                "path": m.path,
                "format": m.format,
                "size_bytes": m.size_bytes,
                "framework": m.framework,
            }
            for m in aibom.models
        ],
        "dataflows": [df.to_mermaid() for df in aibom.dataflows],
    }

    if policy is not None:
        report["policy"] = policy.to_dict()

    return report


def to_findings_json(
    findings: List[Finding],
    architecture_result: Optional["ArchitectureResult"] = None,
) -> Dict[str, Any]:
    """
    Export findings and architecture as JSON for tooling or dashboards.
    Returns {"architecture": {...}, "findings": [...]}.
    """
    findings_data = [
        {
            "id": f.id,
            "title": f.title,
            "category": f.category.value,
            "severity": f.severity.value,
            "description": f.description,
            "file": f.evidence[0].file if f.evidence else None,
            "line": f.evidence[0].line if f.evidence else None,
            "tags": f.tags,
        }
        for f in findings
    ]
    out: Dict[str, Any] = {"findings": findings_data}
    if architecture_result:
        out["architecture"] = architecture_result.to_dict()
    return out


def to_risk_report_markdown(
    aibom: AIBOM,
    policy: PolicyReport | None,
    findings: List[Finding] | None = None,
    architecture_result: Optional["ArchitectureResult"] = None,
) -> str:
    """
    Build a human-readable Enterprise Risk Report in Markdown, including
    plain-language summaries, findings, and Mermaid diagrams.
    """
    lines: list[str] = []
    findings = findings or []
    n_components = len(aibom.components)
    n_models = len(aibom.models)
    n_dataflows = len(aibom.dataflows)
    arch = architecture_result
    lines.append("")
    lines.append(f"**Repository:** `{aibom.repo_path}`")
    lines.append("")

    # Risk score indicator
    risk_score, risk_label = _compute_risk_score(findings, n_models, policy.passed if policy else None)
    risk_emoji = {"High": "🔴", "Medium": "🟠", "Low": "🟢", "Minimal": "✅"}
    lines.append(f"**Risk score:** {risk_emoji.get(risk_label, '')} **{risk_label}** ({risk_score}/100)")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Table of contents (for reports with multiple sections)
    detections = findings_to_detections(findings)
    provider_summaries = summarize_providers(detections)
    toc_sections = ["Executive Summary"]
    if arch and arch.architecture_types and arch.architecture_types != ["Unknown"]:
        toc_sections.append("AI Architecture")
    if provider_summaries:
        toc_sections.append("Provider Usage Summary")
    if findings:
        toc_sections.append("What We Found")
    if aibom.mcp_servers:
        toc_sections.append("MCP Servers")
    if aibom.agent_frameworks:
        toc_sections.append("Agent Frameworks")
    if aibom.components or aibom.models:
        toc_sections.append("AI Component Architecture")
    if aibom.components:
        toc_sections.append("Dependencies")
    if aibom.models:
        toc_sections.append("Model Artifacts")
    if aibom.dataflows:
        toc_sections.append("Code Flows")
    if policy:
        toc_sections.append("Policy Evaluation")
    toc_sections.append("Next Steps")

    lines.append("## Table of Contents")
    lines.append("")
    for s in toc_sections:
        anchor = s.lower().replace(" ", "-").replace("&", "").replace("'", "").replace("_", "-")
        lines.append(f"- [{s}](#{anchor})")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Executive summary (plain language)
    lines.append("## Executive Summary")
    lines.append("")
    summary_parts = []
    if n_components > 0:
        names = ", ".join(c.name for c in aibom.components[:5])
        summary_parts.append(f"This repository has **{n_components}** dependency(ies): **{names}**" + (" and more." if n_components > 5 else "."))
    if n_models > 0:
        summary_parts.append(f"**{n_models}** model artifact(s) were discovered (binary or config files).")
    if aibom.mcp_servers:
        summary_parts.append(f"**{len(aibom.mcp_servers)}** MCP server(s) configured.")
    if aibom.agent_frameworks:
        summary_parts.append(f"**{len(aibom.agent_frameworks)}** agent framework(s): {', '.join(aibom.agent_frameworks)}.")
    if n_dataflows > 0:
        summary_parts.append(f"**{n_dataflows}** code flow(s) were analyzed for AI inference patterns.")
    if findings:
        by_cat = {}
        for f in findings:
            by_cat[f.category.value] = by_cat.get(f.category.value, 0) + 1
        cat_labels = {"surface": "dependencies", "deep": "artifacts", "semantic": "inference calls", "policy": "policy"}
        cats = ", ".join(f"{v} {cat_labels.get(k, k)}" for k, v in by_cat.items())
        summary_parts.append(f"**{len(findings)}** finding(s): {cats}.")
    if arch and arch.architecture_types and arch.architecture_types != ["Unknown"]:
        summary_parts.append(f"**Inferred architecture**: {' + '.join(arch.architecture_types)}.")
    if summary_parts:
        lines.append(" ".join(summary_parts))
    else:
        lines.append("No AI/ML components, models, or inference patterns were detected in this repository.")
    lines.append("")
    lines.append("---")
    lines.append("")

    # AI Architecture (inferred pattern)
    if arch and arch.architecture_types and arch.architecture_types != ["Unknown"]:
        lines.append("## AI Architecture")
        lines.append("")
        lines.append(f"**Inferred pattern(s):** {', '.join(arch.architecture_types)}")
        lines.append("")
        if arch.components:
            lines.append("**Components:**")
            for c in arch.components:
                lines.append(f"- {c}")
        lines.append("")
        lines.append("---")
        lines.append("")

    # Provider Usage Summary (inference calls grouped by provider)
    if provider_summaries:
        lines.append("## Provider Usage Summary")
        lines.append("")
        for s in provider_summaries:
            lines.append(f"**{s.display_name}**: {s.count} call(s)")
            for ex in s.example_files:
                lines.append(f"  - `{ex}`")
            lines.append("")
        lines.append("---")
        lines.append("")

    # Key findings (human-readable) - exclude semantic/inference from this section; Provider Summary covers those
    non_semantic = [f for f in findings if f.category != FindingCategory.SEMANTIC]
    if non_semantic:
        lines.append("## What We Found")
        lines.append("")
        for cat in [FindingCategory.SURFACE, FindingCategory.DEEP, FindingCategory.POLICY]:
            cat_findings = [f for f in findings if f.category == cat]
            if not cat_findings:
                continue
            cat_titles = {"surface": "Dependencies & Imports", "deep": "Model Artifacts", "policy": "Policy Checks"}
            lines.append(f"### {cat_titles.get(cat.value, cat.value.title())}")
            lines.append("")
            max_show = 10
            for f in cat_findings[:max_show]:
                badge = SEVERITY_BADGES.get(f.severity, "•")
                loc = ""
                if f.evidence:
                    e = f.evidence[0]
                    if e.file:
                        loc = f" *(in `{e.file}`" + (f", line {e.line}" if e.line else "") + ")*"
                lines.append(f"- {badge} **{f.title}** — {f.description}{loc}")
            if len(cat_findings) > max_show:
                lines.append(f"*... and {len(cat_findings) - max_show} more*")
            lines.append("")

    # MCP Servers
    if aibom.mcp_servers:
        lines.append("## MCP Servers")
        lines.append("")
        lines.append("Model Context Protocol servers discovered in config:")
        lines.append("")
        for m in aibom.mcp_servers:
            pkg_str = f" ({m.package})" if m.package else ""
            lines.append(f"- **{m.name}** — `{m.config_path}`{pkg_str}")
        lines.append("")

    # Agent Frameworks
    if aibom.agent_frameworks:
        lines.append("## Agent Frameworks")
        lines.append("")
        lines.append("AI agent frameworks in use:")
        lines.append("")
        for af in aibom.agent_frameworks:
            lines.append(f"- **{af}**")
        lines.append("")

    # AI Component Architecture diagram
    component_mermaid = to_ai_component_mermaid(aibom, arch)
    if aibom.components or aibom.models:
        lines.append("## AI Component Architecture")
        lines.append("")
        lines.append("How AI libraries, models, and external APIs connect in this project:")
        lines.append("")
        lines.append("```mermaid")
        lines.append(component_mermaid)
        lines.append("```")
        lines.append("")

    # Dependencies (components) – clearer presentation
    if aibom.components:
        lines.append("## Dependencies")
        lines.append("")
        lines.append("| Package | Version | Type |")
        lines.append("|---------|---------|------|")
        for c in aibom.components[:30]:
            ver = c.version or "—"
            lines.append(f"| {c.name} | {ver} | {c.type.value} |")
        if len(aibom.components) > 30:
            lines.append(f"| ... and {len(aibom.components) - 30} more | | |")
        lines.append("")

    # Models – with human-friendly context
    if aibom.models:
        lines.append("## Model Artifacts")
        lines.append("")
        lines.append("Binary or config files that may represent AI models:")
        lines.append("")
        for m in aibom.models:
            size_str = f"{m.size_bytes:,} bytes" if m.size_bytes else "unknown size"
            lines.append(f"- **{m.name}** — `{m.path}`")
            lines.append(f"  - Format: {m.format or 'unknown'}, Size: {size_str}")
        lines.append("")

    # Data flows – summarized, not raw dump
    if aibom.dataflows:
        lines.append("## Code Flows")
        lines.append("")
        lines.append(f"{n_dataflows} analysis flow(s) were extracted from Python source. ")
        lines.append("Below are the diagrams (expand to view):")
        lines.append("")
        for idx, df in enumerate(aibom.dataflows[:5], start=1):
            lines.append(f"### Flow {idx}")
            lines.append("")
            lines.append("```mermaid")
            lines.append(df.to_mermaid())
            lines.append("```")
            lines.append("")
        if n_dataflows > 5:
            lines.append(f"*... and {n_dataflows - 5} more flow(s) omitted for brevity.*")
            lines.append("")

    if policy is not None:
        lines.append("")
        lines.append("## Policy Evaluation")
        lines.append("")
        lines.append(f"- Overall status: **{'PASSED' if policy.passed else 'FAILED'}**")
        for r in policy.results:
            status = "PASSED" if r.passed else "FAILED"
            lines.append(f"- **{r.rule_id}**: {status} – {r.message}")
        lines.append("")

    # Next steps (actionable)
    lines.append("## Next Steps")
    lines.append("")
    next_steps = []
    if not policy:
        next_steps.append("- Run `aitrace init-policy` to create a policy.yaml for governance checks.")
    if aibom.models:
        next_steps.append("- Review model artifacts and document their provenance and intended use.")
    if findings and any(f.category == FindingCategory.SEMANTIC for f in findings):
        next_steps.append("- Audit AI inference calls for data handling and compliance requirements.")
    if aibom.components:
        next_steps.append("- Keep dependency manifests (requirements.txt, package.json) up to date.")
    if next_steps:
        for s in next_steps:
            lines.append(s)
    else:
        lines.append("- No specific actions recommended at this time.")
    lines.append("")

    return "\n".join(lines)

