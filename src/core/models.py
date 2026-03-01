from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional


class ComponentType(str, Enum):
    LIBRARY = "library"
    SERVICE = "service"
    MODEL = "model"
    DATASET = "dataset"
    INFRASTRUCTURE = "infrastructure"
    APPLICATION = "application"


class FindingCategory(str, Enum):
    SURFACE = "surface"
    DEEP = "deep"
    SEMANTIC = "semantic"
    POLICY = "policy"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Evidence:
    description: str
    file: Optional[str] = None
    line: Optional[int] = None
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Component:
    id: str
    name: str
    type: ComponentType
    version: Optional[str] = None
    purl: Optional[str] = None
    licenses: List[str] = field(default_factory=list)
    properties: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ModelArtifact:
    id: str
    name: str
    path: str
    format: Optional[str] = None
    size_bytes: Optional[int] = None
    framework: Optional[str] = None
    config: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    id: str
    title: str
    category: FindingCategory
    severity: Severity
    description: str
    component_id: Optional[str] = None
    evidence: List[Evidence] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DataFlowNode:
    id: str
    label: str
    kind: str


@dataclass
class DataFlowEdge:
    source: str
    target: str
    label: Optional[str] = None


@dataclass
class DataFlowGraph:
    nodes: List[DataFlowNode] = field(default_factory=list)
    edges: List[DataFlowEdge] = field(default_factory=list)

    def to_mermaid(self) -> str:
        lines = ["flowchart TD"]
        for node in self.nodes:
            lines.append(f"  {node.id}([{node.label}])")
        for edge in self.edges:
            if edge.label:
                lines.append(f"  {edge.source} -->|{edge.label}| {edge.target}")
            else:
                lines.append(f"  {edge.source} --> {edge.target}")
        return "\n".join(lines)


@dataclass
class AIBOM:
    """Unified AI Bill of Materials."""

    repo_path: Path
    components: List[Component] = field(default_factory=list)
    models: List[ModelArtifact] = field(default_factory=list)
    dataflows: List[DataFlowGraph] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PolicyRuleResult:
    rule_id: str
    passed: bool
    severity: Severity
    message: str
    affected_components: List[str] = field(default_factory=list)


@dataclass
class PolicyReport:
    passed: bool
    results: List[PolicyRuleResult] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

