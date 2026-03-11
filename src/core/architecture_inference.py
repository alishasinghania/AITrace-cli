"""
Architecture inference – combines modular detector outputs.

Runs all detectors (RAG, AI Agents, MCP, HuggingFace, Shadow AI) and
produces a unified ArchitectureResult for integration with risk reports
and all output files.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List

from .detectors import (
    DetectionResult,
    detect_agents,
    detect_huggingface,
    detect_mcp,
    detect_rag,
    detect_shadow_ai,
)
from .models import AIBOM

# Blocklist: evidence that is noise, not meaningful AI architecture (applied at detection merge)
_ARCH_COMPONENT_BLOCKLIST = (
    "b64encode", "b64decode", ".encode", ".decode",
    "api_instance.", "api_client.", "taskrequestbody", "agentapi",
    "Config: classic", "Config: benchmark", "Config: forge",
    "agbenchmark_config",
    "self._", "_get_", "_create_", "embeddingmodelresponse", "modelresponse",
    "kwargs", "with_retry", "validate_skill", "run_pipeline", "redis.pipeline",
    "embeddingmodelinfo", "discord.embed", "model file: classic",
    "api_instance.create_agent_task",
    "asyncio.create_task", "tree.create_node", "create_schema", "create_agent_card",
    "finetune_embeddings", "nudge.",  # product-specific, noisy
)


@dataclass
class ArchitectureResult:
    """Unified architecture inference result."""

    architecture_types: List[str]
    components: List[str]
    confidence: str  # "high" | "medium" | "low"
    details: Dict[str, Any] = field(default_factory=dict)
    detector_results: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "architecture_types": self.architecture_types,
            "architecture_type": self.architecture_types[0] if self.architecture_types else "unknown",
            "components": self.components,
            "confidence": self.confidence,
            "details": self.details,
            "detector_results": self.detector_results,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


def infer_architecture(repo_root: Path, aibom: AIBOM) -> ArchitectureResult:
    """
    Run all modular detectors and combine outputs.

    Args:
        repo_root: Repository root path
        aibom: AIBOM from discovery (used for additional context)

    Returns:
        ArchitectureResult with unified architecture_types, components,
        confidence, and per-detector details.
    """
    repo_root = Path(repo_root).resolve()
    detector_results: List[DetectionResult] = []

    # Run detectors
    detector_results.append(detect_rag(repo_root))
    detector_results.append(detect_agents(repo_root))
    detector_results.append(detect_mcp(repo_root))
    detector_results.append(detect_huggingface(repo_root))
    detector_results.append(detect_shadow_ai(repo_root))

    # Collect detected architecture types
    architecture_types: List[str] = []
    all_components: List[str] = []
    confidences: List[str] = []
    details: Dict[str, Any] = {}
    detector_dicts: List[Dict[str, Any]] = []

    for dr in detector_results:
        d = dr.to_dict()
        detector_dicts.append(d)
        if dr.details.get("detected", False) and dr.evidence:
            architecture_types.append(dr.component)
            all_components.extend(dr.evidence[:3])  # Limit per detector
            confidences.append(dr.confidence)
            details[dr.component] = {
                "confidence": dr.confidence,
                "evidence": dr.evidence,
                **(dr.details or {}),
            }

    # Dedupe and filter to meaningful components only (noise reduction at detection)
    seen_comp = set()
    unique_components: List[str] = []
    for c in all_components:
        c_lower = c.lower()
        if c not in seen_comp and not any(bl in c_lower for bl in _ARCH_COMPONENT_BLOCKLIST):
            seen_comp.add(c)
            unique_components.append(c)

    overall_confidence = "high" if "high" in confidences else ("medium" if confidences else "low")

    if not architecture_types:
        architecture_types = ["Unknown"]
        unique_components = []

    return ArchitectureResult(
        architecture_types=architecture_types,
        components=unique_components[:15],
        confidence=overall_confidence,
        details=details,
        detector_results=detector_dicts,
    )
