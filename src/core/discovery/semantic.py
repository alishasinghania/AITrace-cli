"""
High-level semantic AI architecture flow detection.

Produces meaningful AI architecture diagrams instead of low-level function call graphs.
- Detects AI-related flows only (LLM, embeddings, vector stores, agents)
- Maps code elements to semantic nodes (Data Source, Prompt Builder, Embedding Model, etc.)
- Clusters similar flows and generates representative diagrams
- Limits to max 10 nodes, left-to-right layout
- Ignores test files, site-packages, and framework internals
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from ..models import (
    DataFlowEdge,
    DataFlowGraph,
    DataFlowNode,
    Evidence,
    Finding,
    FindingCategory,
    Severity,
)

# ---------------------------------------------------------------------------
# File path patterns to ignore
# ---------------------------------------------------------------------------

IGNORED_PATH_PARTS = {
    "test",
    "tests",
    "__tests__",
    "site-packages",
    "venv",
    ".venv",
    "node_modules",
    ".git",
    "dist",
    "build",
    "egg-info",
    ".eggs",
}

IGNORED_FILE_PATTERNS = (
    r"_test\.py$",
    r"test_.*\.py$",
    r"conftest\.py$",
)

# ---------------------------------------------------------------------------
# Semantic node types and call pattern mappings
# ---------------------------------------------------------------------------

# Maps call attributes/names -> semantic node (kind, label)
# Order matters for flow sequencing. Patterns are matched via startswith or containment.
SEMANTIC_PATTERNS: List[Tuple[Set[str], str, str]] = [
    # (patterns, kind, label)
    ({"PromptTemplate", "ChatPromptTemplate", "HumanMessage", "SystemMessage", "AIMessage"}, "prompt_builder", "Prompt Builder"),
    ({"embed", "encode", "get_embedding", "embedding", "embeddings"}, "embedding_model", "Embedding Model"),
    ({"from_documents", "from_texts", "add_documents", "add_texts"}, "vector_database", "Vector Database"),
    ({"similarity_search", "as_retriever", "max_marginal_relevance"}, "retrieval", "Retrieval"),
    ({"chroma", "chromadb", "pinecone", "weaviate", "qdrant", "faiss", "milvus"}, "vector_database", "Vector Database"),
    ({"chat", "complete", "create", "invoke", "generate", "messages"}, "llm_inference", "LLM Inference"),
    ({"openai", "anthropic", "cohere", "mistral", "vertexai", "generativeai", "bedrock"}, "llm_inference", "LLM Inference"),
    ({"create_react_agent", "create_agent", "stategraph", "crewagent", "crew"}, "agent_orchestrator", "Agent Orchestrator"),
    ({"assistantagent", "userproxyagent", "conversableagent"}, "agent_orchestrator", "Agent Orchestrator"),
    ({"load_documents", "load_and_split", "directory_loader"}, "data_source", "Data Source"),
]

# Additional inference call names for findings (broader than semantic patterns)
AI_CALL_NAMES = {
    "openai", "anthropic", "cohere", "mistral", "vertexai", "generativeai",
    "client", "chat", "complete", "create", "embed", "embedding",
}

AGENT_PATTERNS = (
    "create_react_agent", "create_agent", "crewagent", "crew",
    "stategraph", "stategraphcompiled", "assistantagent", "userproxyagent",
    "conversableagent", "langgraph",
)


def _should_skip_path(path: Path, repo_root: Path) -> bool:
    """Skip test files, site-packages, venv, and framework internals."""
    try:
        rel = path.relative_to(repo_root)
    except ValueError:
        return True
    parts = set(rel.parts)
    if parts & IGNORED_PATH_PARTS:
        return True
    name = path.name.lower()
    for pat in IGNORED_FILE_PATTERNS:
        if re.search(pat, name):
            return True
    return False


def _call_target_name(node: ast.Call) -> Optional[str]:
    """Extract the call target name (attr or id) for pattern matching."""
    if isinstance(node.func, ast.Attribute):
        return node.func.attr.lower()
    if isinstance(node.func, ast.Name):
        return node.func.id.lower()
    return None


def _match_semantic_node(target: str) -> Optional[Tuple[str, str]]:
    """Return (kind, label) if target matches a semantic pattern."""
    t = target.lower()
    for patterns, kind, label in SEMANTIC_PATTERNS:
        if any(t.startswith(p.lower()) or p.lower() in t for p in patterns):
            return (kind, label)
    return None


@dataclass
class SemanticDiscoveryResult:
    dataflows: List[DataFlowGraph]
    findings: List[Finding]


@dataclass
class _SemanticHit:
    """A single detected semantic call."""
    kind: str
    label: str
    provider: str  # e.g. "openai", "anthropic"
    file_path: str
    line: Optional[int]


class _SemanticFlowVisitor(ast.NodeVisitor):
    """Extract AI-related semantic nodes only. No function/helper nodes."""

    def __init__(self, file_path: str, findings: List[Finding], id_prefix: str):
        self.file_path = file_path
        self.findings = findings
        self.id_prefix = id_prefix
        self.call_index = 0
        self.hits: List[_SemanticHit] = []

    def next_id(self) -> str:
        self.call_index += 1
        return f"{self.id_prefix}-{self.call_index:04d}"

    def visit_Call(self, node: ast.Call) -> None:
        target = _call_target_name(node)
        if not target:
            self.generic_visit(node)
            return

        # Map to semantic node
        matched = _match_semantic_node(target)
        if matched:
            kind, label = matched
            provider = target.split(".")[0] if "." in target else target
            self.hits.append(
                _SemanticHit(
                    kind=kind,
                    label=label,
                    provider=provider,
                    file_path=self.file_path,
                    line=getattr(node, "lineno", None),
                )
            )

        # Findings for inference calls
        if any(target.startswith(k) for k in AI_CALL_NAMES):
            self.findings.append(
                Finding(
                    id=self.next_id(),
                    title=f"Model inference call detected: {target}",
                    category=FindingCategory.SEMANTIC,
                    severity=Severity.MEDIUM,
                    description=f"Possible AI inference call to '{target}'.",
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

        if any(p in target.lower() for p in AGENT_PATTERNS):
            self.findings.append(
                Finding(
                    id=self.next_id(),
                    title=f"AI agent pattern detected: {target}",
                    category=FindingCategory.SEMANTIC,
                    severity=Severity.MEDIUM,
                    description=f"Possible agent/orchestrator usage: '{target}'.",
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


# Canonical order for semantic nodes in a flow (left-to-right)
NODE_ORDER = [
    "data_source",
    "prompt_builder",
    "embedding_model",
    "vector_database",
    "retrieval",
    "agent_orchestrator",
    "llm_inference",
    "output",
]


def _build_flow_from_hits(hits: List[_SemanticHit], flow_type: str) -> DataFlowGraph:
    """
    Build a single representative DataFlowGraph from semantic hits.
    Collapses duplicates, orders by NODE_ORDER, limits to 10 nodes.
    """
    seen_kinds: Set[str] = set()
    ordered: List[Tuple[str, str, str]] = []  # (id, kind, label)

    for kind in NODE_ORDER:
        for h in hits:
            if h.kind == kind and kind not in seen_kinds:
                seen_kinds.add(kind)
                nid = f"S_{kind}"
                ordered.append((nid, kind, h.label))
                break

    # Add any unmatched kinds at end
    for h in hits:
        if h.kind not in seen_kinds:
            seen_kinds.add(h.kind)
            nid = f"S_{h.kind}"
            ordered.append((nid, h.kind, h.label))

    nodes = [
        DataFlowNode(id=nid, label=label, kind=kind)
        for nid, kind, label in ordered[:10]
    ]
    edges: List[DataFlowEdge] = []
    for i in range(len(nodes) - 1):
        edges.append(DataFlowEdge(source=nodes[i].id, target=nodes[i + 1].id, label=""))

    return DataFlowGraph(
        nodes=nodes,
        edges=edges,
        flow_type=flow_type,
    )


def _cluster_flows(all_hits: List[Tuple[str, List[_SemanticHit]]]) -> List[DataFlowGraph]:
    """
    Cluster flows by semantic signature (which node types appear).
    Produce one representative diagram per cluster.
    """
    clusters: Dict[FrozenSet[str], List[List[_SemanticHit]]] = {}

    for file_path, hits in all_hits:
        if not hits:
            continue
        kinds = frozenset(h.kind for h in hits)
        if kinds not in clusters:
            clusters[kinds] = []
        clusters[kinds].append(hits)

    # Name flow types by primary pattern
    def flow_type_name(kinds: FrozenSet[str]) -> str:
        if "retrieval" in kinds and "embedding_model" in kinds and "llm_inference" in kinds:
            return "RAG"
        if "agent_orchestrator" in kinds:
            return "AI Agents"
        if "embedding_model" in kinds and "llm_inference" not in kinds:
            return "Embedding Pipeline"
        if "llm_inference" in kinds:
            return "Direct LLM"
        return "AI Flow"

    result: List[DataFlowGraph] = []
    for kinds, hit_lists in clusters.items():
        # Merge all hits in cluster (dedupe by kind for ordering)
        merged: List[_SemanticHit] = []
        for hits in hit_lists:
            merged.extend(hits)
        flow_type = flow_type_name(kinds)
        graph = _build_flow_from_hits(merged, flow_type)
        if graph.nodes:
            result.append(graph)

    return result


def discover_semantic(repo_root: Path) -> SemanticDiscoveryResult:
    """
    Discover high-level semantic AI architecture flows.
    - AI-related flows only (LLM, embeddings, vector stores, agents)
    - Maps to semantic nodes (Data Source, Embedding Model, Vector DB, LLM Inference, etc.)
    - Clusters similar flows into representative diagrams
    - Max 10 nodes per diagram, left-to-right layout
    - Skips test files, site-packages, venv, framework internals
    """
    repo_root = repo_root.resolve()
    findings: List[Finding] = []
    all_hits: List[Tuple[str, List[_SemanticHit]]] = []

    for path in repo_root.rglob("*.py"):
        if _should_skip_path(path, repo_root):
            continue

        try:
            source = path.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(source, filename=str(path))
        except (SyntaxError, OSError):
            continue

        rel_path = str(path.relative_to(repo_root))
        visitor = _SemanticFlowVisitor(rel_path, findings, id_prefix="SEM")
        visitor.visit(tree)

        if visitor.hits:
            all_hits.append((rel_path, visitor.hits))

    dataflows = _cluster_flows(all_hits)
    return SemanticDiscoveryResult(dataflows=dataflows, findings=findings)
