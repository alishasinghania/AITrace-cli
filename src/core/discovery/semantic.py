from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import List

from ..models import (
    DataFlowEdge,
    DataFlowGraph,
    DataFlowNode,
    Evidence,
    Finding,
    FindingCategory,
    Severity,
)

AI_CALL_NAMES = {
    "openai",
    "client",  # openai.Client(), anthropic.Client(), etc.
    "anthropic",
    "cohere",
    "mistral",
    "vertexai",
    "generativeai",
}

AGENT_PATTERNS = (
    "create_react_agent",
    "create_agent",
    "crewagent",
    "crew",
    "stategraph",
    "stategraphcompiled",
    "assistantagent",
    "userproxyagent",
    "conversableagent",
    "langgraph",
)


@dataclass
class SemanticDiscoveryResult:
    dataflows: List[DataFlowGraph]
    findings: List[Finding]


class _InferenceCallVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str, graph: DataFlowGraph, findings: List[Finding], id_prefix: str):
        self.file_path = file_path
        self.graph = graph
        self.findings = findings
        self.id_prefix = id_prefix
        self.call_index = 0

    def next_id(self) -> str:
        self.call_index += 1
        return f"{self.id_prefix}-{self.call_index:04d}"

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        func_id = f"F_{node.name}"
        if not any(n.id == func_id for n in self.graph.nodes):
            self.graph.nodes.append(
                DataFlowNode(id=func_id, label=node.name, kind="function"),
            )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        # Simple heuristic: look for attr or name containing AI_CALL_NAMES
        target_name = None
        if isinstance(node.func, ast.Attribute):
            target_name = node.func.attr.lower()
        elif isinstance(node.func, ast.Name):
            target_name = node.func.id.lower()

        if target_name and any(target_name.startswith(k) for k in AI_CALL_NAMES):
            # Input/preprocess nodes
            src_node = DataFlowNode(id=f"I_{self.call_index}", label="Input", kind="input")
            model_node = DataFlowNode(id=f"M_{self.call_index}", label=target_name, kind="model")
            out_node = DataFlowNode(id=f"O_{self.call_index}", label="Output", kind="output")

            self.graph.nodes.extend([src_node, model_node, out_node])
            self.graph.edges.append(DataFlowEdge(source=src_node.id, target=model_node.id, label="preprocess"))
            self.graph.edges.append(DataFlowEdge(source=model_node.id, target=out_node.id, label="inference"))

            self.findings.append(
                Finding(
                    id=self.next_id(),
                    title=f"Model inference call detected: {target_name}",
                    category=FindingCategory.SEMANTIC,
                    severity=Severity.MEDIUM,
                    description=f"Possible AI inference call to '{target_name}'.",
                    evidence=[
                        Evidence(
                            description="Static call analysis",
                            file=self.file_path,
                            line=getattr(node, "lineno", None),
                        )
                    ],
                    tags=["semantic-flow", "inference-call"],
                )
            )

        # Agent framework patterns (LangGraph, CrewAI, AutoGen, etc.)
        if target_name and any(p in target_name.lower() for p in AGENT_PATTERNS):
            self.findings.append(
                Finding(
                    id=self.next_id(),
                    title=f"AI agent pattern detected: {target_name}",
                    category=FindingCategory.SEMANTIC,
                    severity=Severity.MEDIUM,
                    description=f"Possible agent/orchestrator usage: '{target_name}'.",
                    evidence=[
                        Evidence(
                            description="Static call analysis",
                            file=self.file_path,
                            line=getattr(node, "lineno", None),
                        )
                    ],
                    tags=["ai-agent", "semantic-flow"],
                )
            )

        self.generic_visit(node)


def discover_semantic(repo_root: Path) -> SemanticDiscoveryResult:
    """
    Perform semantic mapping of AI-related calls and derive simple data-flow
    graphs that can be rendered as Mermaid.js diagrams.
    """
    repo_root = repo_root.resolve()
    dataflows: List[DataFlowGraph] = []
    findings: List[Finding] = []

    for path in repo_root.rglob("*.py"):
        try:
            source = path.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(source, filename=str(path))
        except SyntaxError:
            continue

        graph = DataFlowGraph()
        visitor = _InferenceCallVisitor(str(path.relative_to(repo_root)), graph, findings, id_prefix="SEM")
        visitor.visit(tree)

        if graph.nodes:
            dataflows.append(graph)

    return SemanticDiscoveryResult(dataflows=dataflows, findings=findings)

