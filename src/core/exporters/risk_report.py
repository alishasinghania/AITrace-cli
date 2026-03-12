from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List, Optional

from ..models import AIBOM, Finding, FindingCategory, PolicyReport, Severity
from ..risk_scoring import compute_risk_score

if TYPE_CHECKING:
    from ..architecture_inference import ArchitectureResult
from .component_diagram import to_ai_component_mermaid
from .provider_summary import findings_to_detections, summarize_providers

SEVERITY_BADGES = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🟢",
    Severity.INFO: "ℹ️",
}


def _build_executive_insights(
    aibom: AIBOM,
    findings: List[Finding],
    architecture_result: Optional[Any] = None,
    dataflow_analysis: Optional[Any] = None,
    sensitive_exposures: Optional[Any] = None,
    model_supply_chain: Optional[Any] = None,
    prompt_injection_risks: Optional[Any] = None,
    llm_usage: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Build structured executive insights for meaningful metrics.
    Replaces raw counts (e.g. 1650 findings) with actionable summary.
    """
    arch = architecture_result
    insights: Dict[str, Any] = {
        "ai_components_detected": len(aibom.components) + len(aibom.models) + len(aibom.mcp_servers),
        "unique_llm_invocation_patterns": 0,
        "rag_pipelines_detected": 0,
        "agent_frameworks_detected": len(aibom.agent_frameworks or []),
        "agent_tools_detected": len(getattr(aibom, "agent_tools", None) or []),
        "potential_security_issues": 0,
    }

    if llm_usage:
        insights["unique_llm_invocation_patterns"] = len(llm_usage)

    if arch and getattr(arch, "architecture_types", None):
        atypes = arch.architecture_types or []
        if "RAG" in atypes:
            insights["rag_pipelines_detected"] = 1

    # Potential security issues: high-severity findings + sensitive exposures + risky data flows +
    # prompt injection risks + risky model sources
    security_count = 0
    for f in (findings or []):
        if f.severity.value in ("high", "critical"):
            security_count += 1
    if sensitive_exposures and getattr(sensitive_exposures, "sensitive_exposures", None):
        security_count += len(sensitive_exposures.sensitive_exposures)
    if dataflow_analysis and getattr(dataflow_analysis, "data_flows", None):
        security_count += sum(1 for df in dataflow_analysis.data_flows if df.risk in ("high", "medium"))
    if prompt_injection_risks and getattr(prompt_injection_risks, "prompt_injection_risks", None):
        security_count += len([r for r in prompt_injection_risks.prompt_injection_risks if not getattr(r, "sanitized", False)])
    if model_supply_chain:
        agg = getattr(model_supply_chain, "aggregated_models", None)
        if agg:
            security_count += sum(1 for m in agg if m.risk in ("high", "medium"))
    insights["potential_security_issues"] = security_count

    return insights


def _build_summary_with_llm(
    aibom: AIBOM,
    findings: List[Finding],
    llm_usage: Optional[Dict[str, Any]] = None,
    architecture_result: Optional[Any] = None,
    dataflow_analysis: Optional[Any] = None,
    sensitive_exposures: Optional[Any] = None,
    model_supply_chain: Optional[Any] = None,
    prompt_injection_risks: Optional[Any] = None,
) -> Dict[str, Any]:
    """Build summary dict with structured insights and legacy fields for compatibility."""
    insights = _build_executive_insights(
        aibom, findings,
        architecture_result=architecture_result,
        dataflow_analysis=dataflow_analysis,
        sensitive_exposures=sensitive_exposures,
        model_supply_chain=model_supply_chain,
        prompt_injection_risks=prompt_injection_risks,
        llm_usage=llm_usage,
    )
    summary: Dict[str, Any] = {
        "component_count": len(aibom.components),
        "model_count": len(aibom.models),
        "dataflow_count": len(aibom.dataflows),
        "finding_count": len(findings),
        "mcp_server_count": len(aibom.mcp_servers),
        "agent_framework_count": len(aibom.agent_frameworks),
        "agent_tool_count": len(getattr(aibom, "agent_tools", None) or []),
        "executive_insights": insights,
    }
    if llm_usage:
        lp = _build_llm_invocation_patterns(llm_usage)
        if lp:
            summary["llm_invocation_pattern_count"] = lp["pattern_count"]
            summary["llm_total_call_sites"] = lp["total_call_sites"]
    return summary


def _build_provider_summary(
    findings: List[Finding],
    llm_usage: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Build provider summary from llm_usage when available, else from findings."""
    if llm_usage:
        by_provider: Dict[str, Dict[str, Any]] = {}
        for pattern, usage in llm_usage.items():
            if isinstance(usage, dict):
                provider = usage.get("provider", "unknown")
            else:
                provider = getattr(usage, "provider", "unknown") or "unknown"
            if provider not in by_provider:
                by_provider[provider] = {"count": 0, "files": set()}
            count = usage.get("call_sites", 0) if isinstance(usage, dict) else getattr(usage, "call_sites", 0)
            files = usage.get("files", []) if isinstance(usage, dict) else getattr(usage, "files", [])
            by_provider[provider]["count"] += count
            by_provider[provider]["files"].update(files)
        display = {"openai": "OpenAI", "anthropic": "Anthropic", "cohere": "Cohere", "client": "Client (generic)"}
        return [
            {
                "provider": p,
                "display_name": display.get(p, p.replace("_", " ").title()),
                "count": v["count"],
                "example_files": sorted(v["files"])[:3],
            }
            for p, v in sorted(by_provider.items(), key=lambda x: -x[1]["count"])
        ]
    return [
        {"provider": s.provider, "display_name": s.display_name, "count": s.count, "example_files": s.example_files}
        for s in summarize_providers(findings_to_detections(findings or []))
    ]


def _build_llm_invocation_patterns(llm_usage: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Build llm_invocation_patterns section from llm_usage."""
    if not llm_usage:
        return None
    total_sites = 0
    patterns = []
    for pattern, usage in llm_usage.items():
        if isinstance(usage, dict):
            call_sites = usage.get("call_sites", 0)
            files = usage.get("files", [])
            provider = usage.get("provider", "unknown")
        else:
            call_sites = getattr(usage, "call_sites", 0)
            files = getattr(usage, "files", [])
            provider = getattr(usage, "provider", "unknown") or "unknown"
        total_sites += call_sites
        patterns.append(
            {"pattern": pattern, "call_sites": call_sites, "files": files, "provider": provider}
        )
    return {
        "pattern_count": len(llm_usage),
        "total_call_sites": total_sites,
        "patterns": sorted(patterns, key=lambda p: -p["call_sites"]),
    }


def _format_pattern_display_name(pattern: str, provider: str) -> str:
    """Human-readable label: e.g. 'openai.ChatCompletion.create' -> 'OpenAI ChatCompletion'."""
    if provider and provider != "unknown":
        display_provider = {"openai": "OpenAI", "anthropic": "Anthropic", "cohere": "Cohere"}.get(
            provider, provider.replace("_", " ").title()
        )
        rest = pattern.split(".", 1)[-1] if "." in pattern else pattern
        if rest and rest != pattern:
            return f"{display_provider} {rest.rsplit('.', 1)[0] if '.' in rest else rest}"
        return display_provider
    return pattern


def to_risk_report_json(
    aibom: AIBOM,
    policy: PolicyReport | None,
    findings: List[Finding] | None = None,
    architecture_result: Optional["ArchitectureResult"] = None,
    dataflow_analysis: Optional[Any] = None,
    sensitive_exposures: Optional[Any] = None,
    model_supply_chain: Optional[Any] = None,
    prompt_injection_risks: Optional[Any] = None,
    llm_usage: Optional[Dict[str, Any]] = None,
    repo_type: Optional[str] = None,
    architecture_graph: Optional[Dict[str, Any]] = None,
    attack_path_findings: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    Build an Enterprise Risk Report JSON document.
    """
    findings = findings or []
    risk_result = compute_risk_score(
        aibom,
        findings,
        policy,
        architecture_result,
        sensitive_exposures,
        model_supply_chain,
        prompt_injection_risks,
        dataflow_analysis,
        repo_type=repo_type,
    )
    arch_dict = architecture_result.to_dict() if architecture_result else {"architecture_types": ["Unknown"], "components": [], "confidence": "low"}
    report: Dict[str, Any] = {
        "repo": str(aibom.repo_path),
        "repo_type": repo_type or "application",
        "risk_score": {
            "ai_security_score": getattr(risk_result, "ai_security_score", 100 - risk_result.total_score),
            "score": risk_result.total_score,
            "risk_level": risk_result.risk_level,
            "top_risks": getattr(risk_result, "top_risks", [])[:5],
            "repo_type": repo_type or "application",
            "raw_score": risk_result.raw_score,
            "contributing_factors": risk_result.contributing_factors,
            "breakdown": {d.name: {"score": d.score, "max": d.max_score, "contributing_factors": d.contributing_factors} for d in risk_result.dimensions},
            "breakdown_chart": risk_result._chart_lines(),
        },
        "summary": _build_summary_with_llm(
            aibom, findings, llm_usage,
            architecture_result=architecture_result,
            dataflow_analysis=dataflow_analysis,
            sensitive_exposures=sensitive_exposures,
            model_supply_chain=model_supply_chain,
            prompt_injection_risks=prompt_injection_risks,
        ),
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
        "provider_summary": _build_provider_summary(findings, llm_usage),
        "llm_invocation_patterns": _build_llm_invocation_patterns(llm_usage),
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
        "agent_tools": getattr(aibom, "agent_tools", None) or [],
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
        "dataflows": [
            {
                "flow_type": getattr(df, "flow_type", None),
                "diagram": df.to_mermaid(layout="LR"),
                "example_files": getattr(df, "example_files", [])[:5],
                "occurrence_count": getattr(df, "occurrence_count", 1),
            }
            for df in aibom.dataflows
        ],
    }

    if dataflow_analysis is not None:
        report["ai_data_flow_analysis"] = dataflow_analysis.to_dict()
    if sensitive_exposures is not None:
        report["sensitive_exposures"] = sensitive_exposures.to_dict()
    if model_supply_chain is not None:
        report["model_supply_chain"] = model_supply_chain.to_dict()
    if prompt_injection_risks is not None:
        report["prompt_injection_risks"] = prompt_injection_risks.to_dict()

    if policy is not None:
        report["policy"] = policy.to_dict()

    if architecture_graph is not None:
        report["ai_architecture_graph"] = architecture_graph
    if attack_path_findings is not None:
        report["attack_path_findings"] = [
            f.to_dict() if hasattr(f, "to_dict") else f
            for f in attack_path_findings
        ]

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
    dataflow_analysis: Optional[Any] = None,
    sensitive_exposures: Optional[Any] = None,
    model_supply_chain: Optional[Any] = None,
    prompt_injection_risks: Optional[Any] = None,
    llm_usage: Optional[Dict[str, Any]] = None,
    repo_type: Optional[str] = None,
    architecture_graph: Optional[Dict[str, Any]] = None,
    attack_path_findings: Optional[Any] = None,
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
    lines.append(f"**Repository type:** {repo_type or 'application'}")
    if repo_type and repo_type != "application":
        lines.append(f"*(Risk score adjusted for {repo_type}.)*")
    lines.append("")

    # Risk score with 5-dimension breakdown
    risk_result = compute_risk_score(
        aibom,
        findings,
        policy,
        arch,
        sensitive_exposures,
        model_supply_chain,
        prompt_injection_risks,
        dataflow_analysis,
        repo_type=repo_type,
    )
    lines.append("## Risk Assessment")
    lines.append("")
    risk_emoji = {"High": "🔴", "Medium": "🟠", "Low": "🟢", "Minimal": "✅"}
    score_line = f"**Risk score:** {risk_emoji.get(risk_result.risk_level, '')} **{risk_result.risk_level}** ({risk_result.total_score}/100)"
    if risk_result.raw_score is not None and risk_result.repo_type:
        score_line += f" *(adjusted from {risk_result.raw_score} for {risk_result.repo_type})*"
    lines.append(score_line)
    lines.append("")
    lines.append("### AI Risk Breakdown")
    lines.append("")
    for ln in risk_result._chart_lines():
        lines.append(f"    {ln}")
    lines.append("")
    if risk_result.contributing_factors:
        lines.append("**Contributing factors:**")
        for f in risk_result.contributing_factors[:8]:
            lines.append(f"- {f}")
        lines.append("")
    lines.append("---")
    lines.append("")

    # Table of contents (for reports with multiple sections)
    detections = findings_to_detections(findings)
    provider_summaries = summarize_providers(detections)
    llm_patterns = _build_llm_invocation_patterns(llm_usage)
    toc_sections = ["Risk Assessment", "Executive Summary"]
    if arch:
        toc_sections.append("AI Architecture")
    if dataflow_analysis:
        toc_sections.append("AI Data Flow Analysis")
    if sensitive_exposures:
        toc_sections.append("Sensitive Data Exposures")
    if model_supply_chain:
        toc_sections.append("AI Model Supply Chain Risks")
    if prompt_injection_risks:
        toc_sections.append("Prompt Injection Exposure")
    if llm_patterns:
        toc_sections.append("LLM Invocation Patterns")
    elif provider_summaries:
        toc_sections.append("Provider Usage Summary")
    if findings:
        toc_sections.append("What We Found")
    if aibom.mcp_servers:
        toc_sections.append("MCP Servers")
    if aibom.agent_frameworks:
        toc_sections.append("Agent Frameworks")
    if getattr(aibom, "agent_tools", None):
        toc_sections.append("Agent Tools")
    if aibom.components or aibom.models:
        toc_sections.append("AI Component Architecture")
    if aibom.components:
        toc_sections.append("Dependencies")
    if aibom.models:
        toc_sections.append("Model Artifacts")
    if aibom.dataflows:
        toc_sections.append("AI Architecture Flows")
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

    # Executive summary (structured insights, not raw counts)
    insights = _build_executive_insights(
        aibom, findings,
        architecture_result=arch,
        dataflow_analysis=dataflow_analysis,
        sensitive_exposures=sensitive_exposures,
        model_supply_chain=model_supply_chain,
        prompt_injection_risks=prompt_injection_risks,
        llm_usage=llm_usage,
    )
    lines.append("## Executive Summary")
    lines.append("")
    has_any = any(
        insights[k] for k in (
            "ai_components_detected", "unique_llm_invocation_patterns",
            "rag_pipelines_detected", "agent_frameworks_detected",
            "agent_tools_detected", "potential_security_issues"
        )
    )
    if has_any:
        lines.append("- **AI components detected:** " + str(insights["ai_components_detected"]))
        lines.append("- **Unique LLM invocation patterns:** " + str(insights["unique_llm_invocation_patterns"]))
        lines.append("- **RAG pipelines detected:** " + str(insights["rag_pipelines_detected"]))
        af_count = insights["agent_frameworks_detected"]
        af_str = f"{af_count}"
        if aibom.agent_frameworks:
            af_str += f" ({', '.join(aibom.agent_frameworks)})"
        lines.append("- **Agent frameworks detected:** " + af_str)
        at_count = insights.get("agent_tools_detected", len(getattr(aibom, "agent_tools", None) or []))
        at_list = getattr(aibom, "agent_tools", None) or []
        at_str = str(at_count)
        if at_list:
            at_str += f" ({', '.join(at_list)})"
        lines.append("- **Agent tools detected:** " + at_str)
        lines.append("- **Potential security issues:** " + str(insights["potential_security_issues"]))
        if arch and arch.architecture_types and arch.architecture_types != ["Unknown"]:
            lines.append(f"- **Inferred architecture:** {', '.join(arch.architecture_types)}")
        if n_components > 0:
            names = ", ".join(c.name for c in aibom.components[:5])
            lines.append(f"- **Key dependencies:** {names}" + (" and more" if n_components > 5 else ""))
    else:
        lines.append("No AI/ML components, models, or inference patterns were detected in this repository.")
    lines.append("")
    lines.append("---")
    lines.append("")

    # AI Architecture (inferred pattern)
    if arch:
        lines.append("## AI Architecture")
        lines.append("")
        if arch.architecture_types and arch.architecture_types != ["Unknown"]:
            lines.append(f"**Inferred pattern(s):** {', '.join(arch.architecture_types)}")
            lines.append("")
            if arch.components:
                lines.append("**Components:**")
                for c in arch.components:
                    lines.append(f"- {c}")
        else:
            lines.append("No AI architecture patterns detected.")
        # Modular detector results
        detector_results = getattr(arch, "detector_results", None) or []
        if detector_results:
            lines.append("")
            lines.append("**Detector results:**")
            lines.append("")
            lines.append("| Component | Confidence | Evidence |")
            lines.append("|-----------|------------|----------|")
            for dr in detector_results:
                comp = dr.get("component", "—")
                conf = dr.get("confidence", "—")
                ev = dr.get("evidence", [])
                ev_str = ", ".join(str(e)[:40] for e in ev[:3]) if ev else "—"
                if len(ev_str) > 50:
                    ev_str = ev_str[:47] + "..."
                lines.append(f"| {comp} | {conf} | {ev_str} |")
        lines.append("")
        lines.append("---")
        lines.append("")

    # AI Data Flow Analysis (taint analysis: sources -> LLM sinks)
    if dataflow_analysis:
        lines.append("## AI Data Flow Analysis")
        lines.append("")
        if dataflow_analysis.data_flows:
            lines.append("Data flowing from sources into LLM inference calls. Risk is classified by source type:")
            lines.append("")
            lines.append("- **High**: user_input (request, form, argv)")
            lines.append("- **Medium**: external_api (HTTP, DB), environment (env vars)")
            lines.append("- **Low**: file_read, config, internal_variable")
            lines.append("")
            lines.append("| Source Type | Sink | File | Line | Risk |")
            lines.append("|-------------|------|------|------|------|")
            risk_badges = {"high": "🔴 high", "medium": "🟠 medium", "low": "🟢 low"}
            for df in dataflow_analysis.data_flows[:20]:
                line_str = str(df.line) if df.line else "—"
                risk_str = risk_badges.get(df.risk.lower(), df.risk)
                lines.append(f"| {df.source} | {df.sink} | `{df.file}` | {line_str} | {risk_str} |")
            if len(dataflow_analysis.data_flows) > 20:
                lines.append(f"| *... and {len(dataflow_analysis.data_flows) - 20} more flow(s)* | | | | |")
        else:
            lines.append("No sensitive data flows from tracked sources to LLM sinks were detected.")
        lines.append("")
        lines.append("---")
        lines.append("")

    # Sensitive Data Exposures (password, api_key, etc. -> LLM sinks)
    if sensitive_exposures:
        lines.append("## Sensitive Data Exposures")
        lines.append("")
        if sensitive_exposures.sensitive_exposures:
            lines.append("Variables with sensitive names flowing into LLM inference calls:")
            lines.append("")
            lines.append("| Variable | Sink | File | Line | Risk |")
            lines.append("|----------|------|------|------|------|")
            for e in sensitive_exposures.sensitive_exposures[:20]:
                line_str = str(e.line) if e.line else "—"
                risk_badge = "🔴" if e.risk == "critical" else "🟠"
                lines.append(f"| {e.variable} | {e.sink} | `{e.file}` | {line_str} | {risk_badge} {e.risk} |")
            if len(sensitive_exposures.sensitive_exposures) > 20:
                lines.append(f"| *... and {len(sensitive_exposures.sensitive_exposures) - 20} more* | | | | |")
        else:
            lines.append("No sensitive variables (password, api_key, token, etc.) were detected flowing into LLM sinks.")
        lines.append("")
        lines.append("---")
        lines.append("")

    # AI Model Supply Chain Risks (aggregated by model name)
    if model_supply_chain:
        lines.append("## AI Model Supply Chain Risks")
        lines.append("")
        agg = getattr(model_supply_chain, "aggregated_models", None) or []
        if agg:
            lines.append("Models loaded from external sources. Risk by source type:")
            lines.append("")
            lines.append("- **Low**: trusted/verified org (google, meta, huggingface, etc.)")
            lines.append("- **Medium**: unknown org, local/unspecified")
            lines.append("- **High**: remote URLs (GitHub, S3, arbitrary HTTP)")
            lines.append("")
            for m in agg[:20]:
                risk_badge = "🔴" if m.risk == "high" else ("🟠" if m.risk == "medium" else "🟢")
                model_display = m.model[:60] + "…" if len(m.model) > 60 else m.model
                lines.append(f"**`{model_display}`**")
                lines.append(f"- {risk_badge} {m.risk} · Source: {m.source}")
                lines.append(f"- Used in **{m.count}** location(s)")
                for f in m.files[:5]:
                    lines.append(f"  - `{f}`")
                if len(m.files) > 5:
                    lines.append(f"  - *... and {len(m.files) - 5} more*")
                lines.append("")
            if len(agg) > 20:
                lines.append(f"*... and {len(agg) - 20} more model(s)*")
                lines.append("")
        else:
            lines.append("No model loading from external sources (HuggingFace, URLs, S3, etc.) was detected.")
        lines.append("")
        lines.append("---")
        lines.append("")

    # Prompt Injection Exposure (user input → LLM / agent with tools)
    if prompt_injection_risks:
        lines.append("## Prompt Injection Exposure")
        lines.append("")
        if prompt_injection_risks.prompt_injection_risks:
            unmitigated = [r for r in prompt_injection_risks.prompt_injection_risks if not getattr(r, "sanitized", False)]
            if unmitigated:
                lines.append("User input reaching LLM prompts or agents (potential prompt injection):")
            else:
                lines.append("All detected flows pass through sanitization (mitigated).")
            lines.append("")
            lines.append("| Type | Source / Evidence | Severity | Mitigated | File | Line |")
            lines.append("|------|-------------------|----------|-----------|------|------|")
            for r in prompt_injection_risks.prompt_injection_risks[:15]:
                line_str = str(r.line) if r.line else "—"
                rtype = getattr(r, "type", "prompt_injection")
                evidence = r.evidence or (f"{r.input_source} → agent" if r.agent_framework else f"{r.source_file} → {r.sink_file}")
                if len(evidence) > 40:
                    evidence = evidence[:37] + "…"
                sev = getattr(r, "severity", r.risk) if r.risk else getattr(r, "severity", "medium")
                risk_badge = "🔴" if sev == "high" else ("🟠" if sev == "medium" else "🟢")
                mitigated = "✓" if getattr(r, "sanitized", False) else "—"
                fpath = r.file or r.source_file or "—"
                lines.append(f"| {rtype} | {evidence} | {risk_badge} {sev} | {mitigated} | `{fpath}` | {line_str} |")
            if len(prompt_injection_risks.prompt_injection_risks) > 15:
                lines.append(f"| *... and {len(prompt_injection_risks.prompt_injection_risks) - 15} more* | | | | | |")
        else:
            lines.append("No prompt injection exposure (user input → LLM or agent) was detected.")
        lines.append("")
        lines.append("---")
        lines.append("")

    # LLM Invocation Patterns (deduplicated) - compact, cap display to reduce noise
    if llm_patterns:
        _MAX_PATTERNS = 12
        _MAX_FILES_PER_PATTERN = 3
        patterns_list = llm_patterns["patterns"]
        shown = patterns_list[:_MAX_PATTERNS]
        omitted = patterns_list[_MAX_PATTERNS:]
        omitted_sites = sum(p["call_sites"] for p in omitted)
        omitted_count = len(omitted)

        lines.append("## LLM Invocation Patterns")
        lines.append("")
        lines.append(f"**{llm_patterns['pattern_count']}** patterns, **{llm_patterns['total_call_sites']}** total call sites.")
        lines.append("")
        lines.append("| Pattern | Call sites | Files |")
        lines.append("|---------|------------|-------|")
        for p in shown:
            display = _format_pattern_display_name(p["pattern"], p.get("provider", "unknown"))
            if len(display) > 45:
                display = display[:42] + "…"
            ex = ", ".join(f"`{f}`" for f in p["files"][:_MAX_FILES_PER_PATTERN]) or "—"
            if len(p["files"]) > _MAX_FILES_PER_PATTERN:
                ex += f" (+{len(p['files']) - _MAX_FILES_PER_PATTERN})"
            if len(ex) > 55:
                ex = ex[:52] + "…"
            lines.append(f"| {display} | {p['call_sites']} | {ex} |")
        if omitted_count:
            lines.append(f"| *+{omitted_count} more pattern(s), {omitted_sites} call site(s)* | | |")
        lines.append("")
        lines.append("---")
        lines.append("")
    elif provider_summaries:
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

    # Agent Tools
    agent_tools = getattr(aibom, "agent_tools", None) or []
    if agent_tools:
        lines.append("## Agent Tools")
        lines.append("")
        lines.append("Packages used as agent tools (web search, browser automation, git, etc.):")
        lines.append("")
        for at in agent_tools:
            lines.append(f"- **{at}**")
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

    # AI Architecture Flows – high-level semantic flows (not raw function graphs)
    if aibom.dataflows:
        lines.append("## AI Architecture Flows")
        lines.append("")
        lines.append("How data moves through AI components in this codebase. Each diagram shows a **semantic pattern**: ")
        lines.append("the logical path from data sources → embeddings → vector stores → retrieval → LLM inference (or agents).")
        lines.append("")
        total_occurrences = sum(getattr(df, "occurrence_count", 1) for df in aibom.dataflows)
        lines.append(f"**{len(aibom.dataflows)}** distinct pattern(s) across **{total_occurrences}** file(s).")
        lines.append("")
        # Summary table
        lines.append("| Pattern | Files | Example locations |")
        lines.append("|---------|-------|-------------------|")
        for df in aibom.dataflows[:8]:
            ft = getattr(df, "flow_type", None) or "Other"
            cnt = getattr(df, "occurrence_count", 1)
            ex = getattr(df, "example_files", [])
            ex_str = ", ".join(f"`{f}`" for f in ex[:2]) if ex else "—"
            if len(ex_str) > 50:
                ex_str = ex_str[:47] + "..."
            lines.append(f"| {ft} | {cnt} | {ex_str} |")
        if len(aibom.dataflows) > 8:
            lines.append(f"| *... and {len(aibom.dataflows) - 8} more* | | |")
        lines.append("")
        # Diagrams for distinct patterns (deduplicated by flow_type when same structure)
        seen_signatures: set = set()
        for df in aibom.dataflows:
            sig = (df.flow_type, tuple(n.kind for n in df.nodes))
            if sig in seen_signatures:
                continue
            seen_signatures.add(sig)
            if len(seen_signatures) > 5:
                break
            title = df.flow_type or "AI Flow"
            cnt = getattr(df, "occurrence_count", 1)
            header = f"{title} — {cnt} file(s)" if cnt > 1 else title
            lines.append(f"### {header}")
            ex = getattr(df, "example_files", [])
            if ex:
                lines.append(f"*Example: `{ex[0]}`*")
                lines.append("")
            lines.append("```mermaid")
            lines.append(df.to_mermaid(layout="LR"))
            lines.append("```")
            lines.append("")
        remaining = len(aibom.dataflows) - len(seen_signatures)
        if remaining > 0:
            lines.append(f"*{remaining} additional pattern(s) omitted.*")
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

