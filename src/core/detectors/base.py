"""
Base types for modular architecture detectors.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class DetectionResult:
    """Structured output from a single architecture detector."""

    component: str
    confidence: str  # "high" | "medium" | "low"
    evidence: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "component": self.component,
            "confidence": self.confidence,
            "evidence": self.evidence,
            **(self.details or {}),
        }
