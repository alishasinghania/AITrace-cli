from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from .discovery import DeepDiscoveryResult, SemanticDiscoveryResult, SurfaceDiscoveryResult
from .discovery import discover_deep, discover_semantic, discover_surface
from .discovery.surface import AGENT_PACKAGES
from .models import AIBOM, Finding, PolicyReport
from .policy import evaluate_policy, load_policy


@dataclass
class AnalysisResult:
    aibom: AIBOM
    findings: List[Finding]
    policy_report: Optional[PolicyReport] = None


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
        aibom = AIBOM(
            repo_path=self.repo_root,
            components=[*surface.components, *deep.components],
            models=deep.models,
            dataflows=semantic.dataflows,
            mcp_servers=deep.mcp_servers,
            agent_frameworks=agent_frameworks,
        )

        all_findings: List[Finding] = [*surface.findings, *deep.findings, *semantic.findings]

        policy_report: Optional[PolicyReport] = None
        if policy_path is not None and policy_path.exists():
            policy_config = load_policy(policy_path)
            policy_report = evaluate_policy(policy_config, aibom, all_findings)

        return AnalysisResult(aibom=aibom, findings=all_findings, policy_report=policy_report)

