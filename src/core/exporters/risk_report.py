from __future__ import annotations

from typing import Any, Dict

from ..models import AIBOM, PolicyReport


def to_risk_report_json(aibom: AIBOM, policy: PolicyReport | None) -> Dict[str, Any]:
    """
    Build an Enterprise Risk Report JSON document.
    """
    report: Dict[str, Any] = {
        "repo": str(aibom.repo_path),
        "summary": {
            "component_count": len(aibom.components),
            "model_count": len(aibom.models),
            "dataflow_count": len(aibom.dataflows),
        },
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


def to_risk_report_markdown(aibom: AIBOM, policy: PolicyReport | None) -> str:
    """
    Build a human-readable Enterprise Risk Report in Markdown, including
    Mermaid diagrams.
    """
    lines: list[str] = []
    lines.append(f"# AITrace Enterprise Risk Report")
    lines.append("")
    lines.append(f"Repository: `{aibom.repo_path}`")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Components: **{len(aibom.components)}**")
    lines.append(f"- Models: **{len(aibom.models)}**")
    lines.append(f"- Dataflows: **{len(aibom.dataflows)}**")

    if aibom.models:
        lines.append("")
        lines.append("## Models")
        lines.append("")
        for m in aibom.models:
            lines.append(f"- **{m.name}** (`{m.path}`) – format: `{m.format}`, size: `{m.size_bytes}` bytes")

    if aibom.dataflows:
        lines.append("")
        lines.append("## Data Flows")
        lines.append("")
        for idx, df in enumerate(aibom.dataflows, start=1):
            lines.append(f"### Flow {idx}")
            lines.append("")
            lines.append("```mermaid")
            lines.append(df.to_mermaid())
            lines.append("```")
            lines.append("")

    if policy is not None:
        lines.append("")
        lines.append("## Policy Evaluation")
        lines.append("")
        lines.append(f"- Overall status: **{'PASSED' if policy.passed else 'FAILED'}**")
        for r in policy.results:
            status = "PASSED" if r.passed else "FAILED"
            lines.append(f"- **{r.rule_id}**: {status} – {r.message}")

    return "\n".join(lines)

