from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from .architecture_graph import build_architecture_graph
from .ai_attack_path_analyzer import analyze_attack_paths
from .architecture_inference import ArchitectureResult, infer_architecture
from .dataflow_analyzer import DataFlowAnalysisResult, analyze_dataflows
from .model_supply_chain_analyzer import ModelSupplyChainResult, analyze_model_supply_chain
from .prompt_injection_detector import PromptInjectionResult, analyze_prompt_injection
from .sensitive_data_detector import SensitiveExposureResult, analyze_sensitive_exposures
from .discovery import DeepDiscoveryResult, SemanticDiscoveryResult, SurfaceDiscoveryResult
from .discovery import discover_deep, discover_semantic, discover_surface
from .discovery.surface import AGENT_PACKAGES, AGENT_TOOL_PACKAGES
from .models import AIBOM, AttackPathFinding, Finding, PolicyReport
from .policy import evaluate_policy, load_policy
from .repo_classifier import classify_repository


@dataclass
class AnalysisResult:
    aibom: AIBOM
    findings: List[Finding]
    policy_report: Optional[PolicyReport] = None
    dataflow_analysis: Optional[DataFlowAnalysisResult] = None
    sensitive_exposures: Optional[SensitiveExposureResult] = None
    model_supply_chain: Optional[ModelSupplyChainResult] = None
    prompt_injection_risks: Optional[PromptInjectionResult] = None
    llm_usage: Optional[dict] = None  # Dict[str, LLMPatternUsage] - deduplicated patterns
    repo_type: str = "application"  # "application" | "library" | "framework"
    architecture_result: Optional[ArchitectureResult] = None
    architecture_graph: Optional[dict] = None  # {nodes, edges} from build_architecture_graph
    attack_path_findings: Optional[List[AttackPathFinding]] = None


class AITraceEngine:
    """
    High-level orchestration engine that runs all discovery stages and optional
    policy evaluation.
    """

    def __init__(self, repo_root: Path) -> None:
        self.repo_root = repo_root.resolve()

    def analyze(self, policy_path: Optional[Path] = None) -> AnalysisResult:
        # Surface discovery
        surface: SurfaceDiscoveryResult = discover_surface(self.repo_root)

        # Deep inspection
        deep: DeepDiscoveryResult = discover_deep(self.repo_root)

        # Semantic mapping
        semantic: SemanticDiscoveryResult = discover_semantic(self.repo_root)

        agent_frameworks = [
            c.name for c in surface.components
            if c.name and c.name.lower() in AGENT_PACKAGES
        ]
        agent_tools = [
            c.name for c in surface.components
            if c.name and c.name.lower().replace("-", "_") in AGENT_TOOL_PACKAGES
        ]
        aibom = AIBOM(
            repo_path=self.repo_root,
            components=[*surface.components, *deep.components],
            models=deep.models,
            dataflows=semantic.dataflows,
            mcp_servers=deep.mcp_servers,
            agent_frameworks=agent_frameworks,
            agent_tools=agent_tools,
        )

        all_findings: List[Finding] = [*surface.findings, *deep.findings, *semantic.findings]

        policy_report: Optional[PolicyReport] = None
        if policy_path is not None and policy_path.exists():
            policy_config = load_policy(policy_path)
            policy_report = evaluate_policy(policy_config, aibom, all_findings)

        dataflow_analysis = analyze_dataflows(self.repo_root)
        sensitive_exposures = analyze_sensitive_exposures(self.repo_root)
        model_supply_chain = analyze_model_supply_chain(self.repo_root, policy_path=policy_path)
        prompt_injection_risks = analyze_prompt_injection(self.repo_root, dataflow_analysis=dataflow_analysis)
        repo_type = classify_repository(self.repo_root)

        architecture_result = infer_architecture(self.repo_root, aibom)
        architecture_graph = build_architecture_graph(
            aibom,
            dataflow_analysis=dataflow_analysis,
            semantic_result=semantic,
            architecture_result=architecture_result,
        )
        attack_path_findings = analyze_attack_paths(architecture_graph)

        return AnalysisResult(
            aibom=aibom,
            findings=all_findings,
            policy_report=policy_report,
            dataflow_analysis=dataflow_analysis,
            sensitive_exposures=sensitive_exposures,
            model_supply_chain=model_supply_chain,
            prompt_injection_risks=prompt_injection_risks,
            llm_usage=semantic.llm_usage,
            repo_type=repo_type,
            architecture_result=architecture_result,
            architecture_graph=architecture_graph,
            attack_path_findings=attack_path_findings,
        )

