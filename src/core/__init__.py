"""
AITrace core package.

Provides the main analysis engine, discovery modules, security analyzers,
policy enforcement, and export utilities for generating AI Bills of Materials
(AIBOM) and security reports.

Package structure:
  core.analyzers   — taint analysis, injection detection, supply chain
  core.detectors   — AI framework and pattern detectors
  core.discovery   — surface, deep, and semantic discovery
  core.exporters   — CycloneDX, SPDX, risk reports, Mermaid
  core.features    — LLM verifier, exploit synthesizer, credentials
  core.governance  — policy, risk scoring, repo classification
  core.utils       — shared AST utilities
"""

from .analyzers.architecture_inference import ArchitectureResult, infer_architecture  # noqa: F401
from .engine import AITraceEngine, AnalysisResult  # noqa: F401

__all__ = [
    "AITraceEngine",
    "AnalysisResult",
    "ArchitectureResult",
    "infer_architecture",
]
