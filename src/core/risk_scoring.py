"""
AI Security Risk Scoring Engine for AITrace.

Evaluates risk across five dimensions with presence-based scoring:
1. External AI Exposure (max 25)
2. Data Exposure to LLMs (max 25)
3. Execution Risk from Agents or Tools (max 20)
4. Architecture Complexity (max 15)
5. Missing AI Security Controls (max 15)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from .models import AIBOM, Finding, FindingCategory, PolicyReport

if TYPE_CHECKING:
    from .architecture_inference import ArchitectureResult

# Dimension config: (name, max_score)
DIMENSIONS = [
    ("External AI Exposure", 25),
    ("Data Exposure to LLMs", 25),
    ("Execution Risk", 20),
    ("Architecture Complexity", 15),
    ("Missing AI Security Controls", 15),
]


@dataclass
class RiskDimension:
    """Single dimension score with contributing factors."""

    name: str
    score: int
    max_score: int
    contributing_factors: List[str] = field(default_factory=list)


@dataclass
class RiskScoreResult:
    """Full risk assessment with breakdown and normalized total."""

    total_score: int
    risk_level: str
    dimensions: List[RiskDimension]
    contributing_factors: List[str] = field(default_factory=list)
    raw_score: Optional[int] = None  # Before repo_type multiplier, when applied
    repo_type: Optional[str] = None  # When multiplier was applied

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": self.total_score,
            "risk_level": self.risk_level,
            "contributing_factors": self.contributing_factors,
            "breakdown": {
                d.name: {
                    "score": d.score,
                    "max": d.max_score,
                    "contributing_factors": d.contributing_factors,
                }
                for d in self.dimensions
            },
            "breakdown_chart": self._chart_lines(),
        }

    def _chart_lines(self) -> List[str]:
        """Generate ASCII bar chart lines."""
        lines = []
        bar_len = 10
        for d in self.dimensions:
            filled = int(bar_len * d.score / d.max_score) if d.max_score else 0
            bar = "█" * filled + "░" * (bar_len - filled)
            short_name = d.name.replace("Architecture Complexity", "Architecture Risk")
            short_name = short_name.replace("Missing AI Security Controls", "Missing Controls")
            short_name = short_name.replace("External AI Exposure", "External Exposure")
            short_name = short_name.replace("Data Exposure to LLMs", "Data Exposure")
            short_name = short_name.replace("Execution Risk from Agents or Tools", "Execution Risk")
            lines.append(f"{short_name:<22} {bar} {d.score}")
        return lines


def _risk_level_from_score(score: int) -> str:
    """Map total score to risk level."""
    if score >= 70:
        return "High"
    if score >= 40:
        return "Medium"
    if score >= 15:
        return "Low"
    return "Minimal"


def compute_risk_score(
    aibom: AIBOM,
    findings: List[Finding],
    policy: Optional[PolicyReport],
    architecture_result: Optional["ArchitectureResult"],
    sensitive_exposures: Optional[Any] = None,
    model_supply_chain: Optional[Any] = None,
    prompt_injection_risks: Optional[Any] = None,
    dataflow_analysis: Optional[Any] = None,
    repo_type: Optional[str] = None,
) -> RiskScoreResult:
    """
    Compute AI security risk across five dimensions.
    Uses presence-based scoring (factors present/absent, not counts).
    """
    findings = findings or []
    arch = architecture_result

    # Helper: detector detected component
    def detector_detected(component: str) -> bool:
        if not arch or not getattr(arch, "detector_results", None):
            return False
        for dr in arch.detector_results:
            if dr.get("component") == component and dr.get("details", {}).get("detected"):
                return True
        return False

    # Helper: architecture types present
    arch_types = (arch.architecture_types or []) if arch else []
    has_rag = detector_detected("RAG") or "RAG" in arch_types
    has_agents = detector_detected("AI Agents") or "AI Agents" in arch_types
    has_shadow_ai = detector_detected("Shadow AI")
    has_mcp = bool(aibom.mcp_servers) or detector_detected("MCP Servers")
    has_hf = detector_detected("HuggingFace Local Models")

    # Inference calls (semantic findings)
    semantic_findings = [f for f in findings if f.category == FindingCategory.SEMANTIC]
    has_inference = bool(semantic_findings)
    has_providers = has_inference  # Inference calls imply external provider usage

    # Policy state
    has_policy = policy is not None
    policy_passed = policy.passed if policy else None

    dimensions: List[RiskDimension] = []

    # 1. External AI Exposure (max 25)
    ext_score = 0
    ext_factors: List[str] = []
    risky_models = []
    if model_supply_chain:
        agg = getattr(model_supply_chain, "aggregated_models", None)
        if agg:
            risky_models = [m for m in agg if m.risk in ("high", "medium")]
        elif getattr(model_supply_chain, "model_sources", None):
            risky_models = [m for m in model_supply_chain.model_sources if m.risk in ("high", "medium")]
    if risky_models:
        ext_score += min(10, 5 + len(risky_models) * 2)
        ext_factors.append(
            f"Models loaded from external/unknown sources ({len(risky_models)} source(s))"
        )
    if has_shadow_ai:
        ext_score += 15
        ext_factors.append("Direct API calls to LLM providers (Shadow AI)")
    if has_mcp:
        ext_score += 10
        ext_factors.append("MCP servers configured")
    if has_providers and not has_shadow_ai:
        ext_score += 12
        ext_factors.append("External AI/LLM usage detected")
    dimensions.append(
        RiskDimension("External AI Exposure", min(ext_score, 25), 25, ext_factors)
    )

    # 2. Data Exposure to LLMs (max 25)
    data_score = 0
    data_factors: List[str] = []
    has_sensitive = False
    has_critical_sensitive = False
    has_data_flows = False
    if sensitive_exposures and getattr(sensitive_exposures, "sensitive_exposures", None):
        expos = sensitive_exposures.sensitive_exposures
        if expos:
            has_sensitive = True
            has_critical_sensitive = any(e.risk == "critical" for e in expos)
            data_score += 25 if has_critical_sensitive else 20
            data_factors.append(
                f"Sensitive data (password, api_key, etc.) flows to LLM sinks ({len(expos)} exposure(s))"
            )
    if dataflow_analysis and getattr(dataflow_analysis, "data_flows", None) and not has_sensitive:
        flows = dataflow_analysis.data_flows
        if flows:
            has_data_flows = True
            data_score += min(18, 10 + len(flows) * 2)
            data_factors.append(
                f"Untrusted data flows to LLM sinks ({len(flows)} flow(s))"
            )
    if has_inference and not has_sensitive:
        data_score += 15
        data_factors.append("Inference calls send data to LLMs")
    if has_rag and not has_sensitive:
        data_score += 10
        data_factors.append("RAG pipeline: embeddings and vector store data flow")
    if aibom.models and not has_sensitive:
        data_score += 5
        data_factors.append("Model artifacts (potential data exposure)")
    dimensions.append(
        RiskDimension("Data Exposure to LLMs", min(data_score, 25), 25, data_factors)
    )

    # 3. Execution Risk from Agents or Tools (max 20)
    exec_score = 0
    exec_factors: List[str] = []
    has_prompt_injection = False
    if prompt_injection_risks and getattr(prompt_injection_risks, "prompt_injection_risks", None):
        risks = prompt_injection_risks.prompt_injection_risks
        if risks:
            has_prompt_injection = True
            exec_score += 20
            exec_factors.append(
                f"Prompt injection exposure: user input to agent with tools ({len(risks)} risk(s))"
            )
    if has_agents and not has_prompt_injection:
        exec_score += 15
        exec_factors.append("AI agent frameworks (LangChain, LangGraph, etc.)")
    if has_mcp and not has_prompt_injection:
        exec_score += 10
        exec_factors.append("MCP servers (tool execution)")
    dimensions.append(
        RiskDimension("Execution Risk", min(exec_score, 20), 20, exec_factors)
    )

    # 4. Architecture Complexity (max 15)
    arch_score = 0
    arch_factors: List[str] = []
    if has_rag:
        arch_score += 8
        arch_factors.append("RAG pipeline detected")
    if has_agents:
        arch_score += 5
        arch_factors.append("AI agents architecture")
    if len(aibom.components) + len(aibom.models) >= 3:
        arch_score += 5
        arch_factors.append("Multiple AI components")
    if aibom.dataflows:
        arch_score += 5
        arch_factors.append("Complex data flows")
    dimensions.append(
        RiskDimension("Architecture Complexity", min(arch_score, 15), 15, arch_factors)
    )

    # 5. Missing AI Security Controls (max 15)
    ctrl_score = 0
    ctrl_factors: List[str] = []
    if not has_policy:
        ctrl_score += 10
        ctrl_factors.append("No policy.yaml governance file")
    elif policy_passed is False:
        ctrl_score += 10
        ctrl_factors.append("Policy evaluation failed")
    if has_policy and policy and not all(r.passed for r in policy.results):
        ctrl_score += 5
        if "Policy evaluation failed" not in ctrl_factors:
            ctrl_factors.append("Policy violations present")
    dimensions.append(
        RiskDimension("Missing AI Security Controls", min(ctrl_score, 15), 15, ctrl_factors)
    )

    # Total (capped at 100)
    raw_total = sum(d.score for d in dimensions)
    raw_total = min(raw_total, 100)
    total = raw_total

    # Repo-type multiplier to reduce false positives
    applied_repo_type: Optional[str] = None
    if repo_type == "library":
        total = int(raw_total * 0.4)
        applied_repo_type = "library"
    elif repo_type == "framework":
        total = int(raw_total * 0.5)
        applied_repo_type = "framework"
    total = min(total, 100)

    # Contributing factors (top-level)
    all_factors: List[str] = []
    for d in dimensions:
        all_factors.extend(d.contributing_factors)
    all_factors = list(dict.fromkeys(all_factors))  # dedupe, preserve order

    if applied_repo_type:
        all_factors.append(f"Repository type: {applied_repo_type} (score {raw_total} → {total})")

    return RiskScoreResult(
        total_score=total,
        risk_level=_risk_level_from_score(total),
        dimensions=dimensions,
        contributing_factors=all_factors,
        raw_score=raw_total if applied_repo_type else None,
        repo_type=applied_repo_type,
    )
