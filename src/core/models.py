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
class MCPServer:
    """Discovered MCP (Model Context Protocol) server from config."""

    id: str
    name: str
    config_path: str
    command: Optional[str] = None
    args: List[str] = field(default_factory=list)
    package: Optional[str] = None


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
class LLMPatternUsage:
    """Deduplicated LLM invocation pattern with call sites and files."""

    pattern: str
    call_sites: int
    files: List[str]
    provider: str = ""  # e.g. "openai", "anthropic" for display

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pattern": self.pattern,
            "call_sites": self.call_sites,
            "files": self.files,
            "provider": self.provider,
        }


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
    """High-level semantic AI architecture flow (not raw function graphs)."""

    nodes: List[DataFlowNode] = field(default_factory=list)
    edges: List[DataFlowEdge] = field(default_factory=list)
    flow_type: Optional[str] = None  # e.g. "RAG", "Direct LLM", "Embedding Pipeline"
    example_files: List[str] = field(default_factory=list)  # sample file paths for context
    occurrence_count: int = 1  # how many files/flows contributed to this pattern

    def _escape_mermaid_label(self, s: str) -> str:
        return s.replace('"', "&quot;")

    def to_mermaid(self, layout: str = "LR") -> str:
        """Render as Mermaid flowchart. layout: LR (left-to-right) or TD (top-down)."""
        direction = layout.upper() if layout in ("LR", "TD", "BT", "RL") else "LR"
        kept = self.nodes[:10]  # Max 10 nodes
        kept_ids = {n.id for n in kept}
        lines = [f"flowchart {direction}"]
        for node in kept:
            label = self._escape_mermaid_label(node.label)
            lines.append(f'  {node.id}(["{label}"])')
        for edge in self.edges:
            if edge.source in kept_ids and edge.target in kept_ids:
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
    mcp_servers: List[MCPServer] = field(default_factory=list)
    agent_frameworks: List[str] = field(default_factory=list)  # names of detected agent packages
    agent_tools: List[str] = field(default_factory=list)  # names of detected agent tool packages

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

