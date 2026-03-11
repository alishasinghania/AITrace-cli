"""
AITrace core package.

Provides the main analysis engine, discovery modules, policy evaluation,
and export utilities for generating AI Bills of Materials (AIBOM) and
associated governance reports.
"""

from .architecture_detector import (  # noqa: F401
    ArchitectureResult,
    ScanInput,
    detect_architecture,
    scan_from_aibom,
)
from .engine import AITraceEngine, AnalysisResult  # noqa: F401
