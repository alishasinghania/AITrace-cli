"""
Discovery layer for AITrace.

Provides:
- Surface discovery of dependencies and cloud providers.
- Deep inspection of model artefacts and configuration.
- Semantic mapping of data flows for AI components.
"""

from .surface import SurfaceDiscoveryResult, discover_surface  # noqa: F401
from .deep import DeepDiscoveryResult, discover_deep  # noqa: F401
from .semantic import SemanticDiscoveryResult, discover_semantic  # noqa: F401

