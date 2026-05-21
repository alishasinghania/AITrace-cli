"""
AITrace core package.

Provides the main analysis engine, discovery modules, policy evaluation,
and export utilities for generating AI Bills of Materials (AIBOM) and
associated governance reports.
"""

from .analyzers.architecture_inference import ArchitectureResult, infer_architecture  # noqa: F401
from .engine import AITraceEngine, AnalysisResult  # noqa: F401
