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
from collections import defaultdict
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
    LLMPatternUsage,
    Severity,
)

# ---------------------------------------------------------------------------
# File path patterns (uses shared should_skip_path from detectors)
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Semantic node types and call pattern mappings
# ---------------------------------------------------------------------------

# Maps call attributes/names -> semantic node (kind, label)
# Order matters. Use specific patterns; generic ones require chain context to avoid FPs.
# Embedding: exclude "encode" (matches url.encode, base64.b64encode)
SEMANTIC_PATTERNS: List[Tuple[Set[str], str, str]] = [
    ({"PromptTemplate", "ChatPromptTemplate", "HumanMessage", "SystemMessage", "AIMessage"}, "prompt_builder", "Prompt Builder"),
    ({"embed", "get_embedding", "embedding", "embeddings", "embed_documents", "embed_query"}, "embedding_model", "Embedding Model"),
    ({"from_documents", "from_texts", "add_documents", "add_texts"}, "vector_database", "Vector Database"),
    ({"similarity_search", "as_retriever", "max_marginal_relevance"}, "retrieval", "Retrieval"),
    ({"chroma", "chromadb", "pinecone", "weaviate", "qdrant", "faiss", "milvus"}, "vector_database", "Vector Database"),
    ({"load_documents", "load_and_split", "directory_loader"}, "data_source", "Data Source"),
]
# LLM: generic "create"/"invoke" need chain context; provider names are direct matches
SEMANTIC_LLM_TARGETS = {"chat", "complete", "create", "invoke", "generate", "messages"}
SEMANTIC_LLM_CHAIN_REQUIRED = {"openai", "anthropic", "cohere", "mistral", "vertexai", "generativeai", "bedrock", "litellm", "chat", "completion", "messages"}

# Targets that are NOT LLM inference (config, reflection, embeddings, UI)
LLM_TARGET_BLOCKLIST = frozenset({
    "init",  # vertexai.init(), client.init() - configuration
    "embed", "embed_documents", "embed_query", "get_embedding", "encode",  # embedding API
    "class_name", "load_class", "from_name", "get_class",  # reflection/loading
})

# Chain substrings that indicate non-LLM call sites
LLM_CHAIN_BLOCKLIST = (
    "asyncio", "tree.", "redis.", "api_instance", "api_client",
    "pn.", "panel.",  # Panel dashboard UI (pn.chat.ChatMessage, etc.)
    ".init",  # vertexai.init, client.init - initialization not inference
    "gmail",  # Gmail API messages - not LLM chat
    "clientv2", "asyncclientv2",  # Cohere embeddings API (ClientV2), not chat
    "chatmessage", "chatinterface",  # Panel UI components when in pn. chain
)

# Bare self.chat with no llm/client in chain = interface/abstract, often not inference
LLM_BARE_SELF_CHAT = ("self", "chat")  # chain for self.chat (no llm/client)

# Known LLM providers - for strict matching of generic targets
LLM_KNOWN_PROVIDERS = frozenset(
    {"openai", "anthropic", "cohere", "mistral", "vertexai", "generativeai", "bedrock", "litellm"}
)
# Agent: require framework in chain to avoid create_agent_task, create_agent_card
SEMANTIC_AGENT_SPECIFIC = {"create_react_agent", "stategraph", "crewagent", "crew", "assistantagent", "userproxyagent", "conversableagent"}
SEMANTIC_AGENT_REQUIRES_CHAIN = {"create_agent"}  # create_agent needs langchain/crew in chain

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
    """Skip non-production code (uses aitrace.yaml ignore_paths)."""
    from ..detectors._ast_utils import should_skip_path
    return should_skip_path(path, repo_root)


def _call_target_name(node: ast.Call) -> Optional[str]:
    """Extract the call target name (attr or id) for pattern matching."""
    if isinstance(node.func, ast.Attribute):
        return node.func.attr.lower()
    if isinstance(node.func, ast.Name):
        return node.func.id.lower()
    return None


def _get_call_chain(node: ast.Call) -> List[str]:
    """Get full call chain e.g. ['openai', 'ChatCompletion', 'create']."""
    chain: List[str] = []
    n = node.func
    while isinstance(n, ast.Attribute):
        chain.append(n.attr)
        n = n.value
    if isinstance(n, ast.Name):
        chain.append(n.id)
    return list(reversed(chain))


def _match_semantic_node(target: str, chain: List[str]) -> Optional[Tuple[str, str]]:
    """Return (kind, label) if target matches a semantic pattern. Uses chain to avoid FPs."""
    t = target.lower()
    chain_lower = [c.lower() for c in chain]
    chain_set = set(chain_lower)
    chain_str = ".".join(chain_lower)

    # Standard patterns (no chain guard)
    for patterns, kind, label in SEMANTIC_PATTERNS:
        if any(t.startswith(p.lower()) or p.lower() in t for p in patterns):
            return (kind, label)

    # LLM: same blocklists as _is_llm_inference_call for consistency
    if t in LLM_TARGET_BLOCKLIST or any(bl in t for bl in LLM_TARGET_BLOCKLIST):
        return None
    if any(bl in chain_str for bl in LLM_CHAIN_BLOCKLIST):
        return None
    if len(chain_lower) == 2 and tuple(chain_lower) == LLM_BARE_SELF_CHAT:
        return None
    if "cohere" in chain_set and (chain_set & {"clientv2", "asyncclientv2"}):
        return None

    if t == "messages" and not (chain_set & LLM_KNOWN_PROVIDERS):
        return None
    if t in SEMANTIC_LLM_TARGETS or any(tt in t for tt in SEMANTIC_LLM_TARGETS):
        if chain_set & SEMANTIC_LLM_CHAIN_REQUIRED:
            return ("llm_inference", "LLM Inference")
    if chain_set & LLM_KNOWN_PROVIDERS:
        return ("llm_inference", "LLM Inference")

    # Agent: create_agent only with framework; skip api_instance.create_agent_task etc.
    if any(bl in chain_str for bl in ("api_instance", "api_client", "agentapi")):
        return None
    for p in SEMANTIC_AGENT_SPECIFIC:
        if p in t or t.startswith(p):
            return ("agent_orchestrator", "Agent Orchestrator")
    if "create_agent" in t or t == "create_agent":
        if any(fw in chain_str for fw in ("langchain", "langgraph", "crew", "crewai")):
            return ("agent_orchestrator", "Agent Orchestrator")
    return None


@dataclass
class SemanticDiscoveryResult:
    dataflows: List[DataFlowGraph]
    findings: List[Finding]
    llm_usage: Dict[str, LLMPatternUsage] = field(default_factory=dict)


@dataclass
class _SemanticHit:
    """A single detected semantic call."""
    kind: str
    label: str
    provider: str  # e.g. "openai", "anthropic"
    file_path: str
    line: Optional[int]


def _is_llm_inference_call(target: str, chain: List[str]) -> Optional[str]:
    """Return pattern string if this is an LLM inference call, else None."""
    chain_lower = [c.lower() for c in chain]
    chain_set = set(chain_lower)
    chain_str = ".".join(chain_lower)
    t = target.lower()

    # Target blocklist: init, embedding APIs, reflection
    if t in LLM_TARGET_BLOCKLIST or any(bl in t for bl in LLM_TARGET_BLOCKLIST):
        return None

    # Chain blocklist: UI libs, config, non-LLM APIs
    if any(bl in chain_str for bl in LLM_CHAIN_BLOCKLIST):
        return None

    # Bare self.chat (no llm/client) = abstract/interface, not inference
    if len(chain_lower) == 2 and tuple(chain_lower) == LLM_BARE_SELF_CHAT:
        return None

    # Cohere ClientV2/AsyncClientV2 = embeddings API, not chat
    if "cohere" in chain_set and (chain_set & {"clientv2", "asyncclientv2"}):
        return None

    # Target "messages" without known provider = often Gmail/Google Chat API, not LLM
    if t == "messages" and not (chain_set & LLM_KNOWN_PROVIDERS):
        return None

    if chain_set & LLM_KNOWN_PROVIDERS:
        return ".".join(chain) if chain else target
    if t in SEMANTIC_LLM_TARGETS or any(tt in t for tt in SEMANTIC_LLM_TARGETS):
        if chain_set & SEMANTIC_LLM_CHAIN_REQUIRED:
            return ".".join(chain) if chain else target
    return None


def _infer_provider_from_pattern(pattern: str) -> str:
    """Extract provider (first segment) from pattern e.g. openai.ChatCompletion.create -> openai."""
    parts = pattern.split(".")
    if parts:
        p = parts[0].lower()
        if p in ("openai", "anthropic", "cohere", "mistral", "vertexai", "generativeai", "bedrock"):
            return p
        if p == "client":
            return "client"
    return "unknown"


class _SemanticFlowVisitor(ast.NodeVisitor):
    """Extract AI-related semantic nodes only. No function/helper nodes."""

    def __init__(
        self,
        file_path: str,
        findings: List[Finding],
        id_prefix: str,
        llm_calls: Optional[List[Tuple[str, str]]] = None,
    ):
        self.file_path = file_path
        self.findings = findings
        self.id_prefix = id_prefix
        self.call_index = 0
        self.hits: List[_SemanticHit] = []
        self.llm_calls: List[Tuple[str, str]] = llm_calls if llm_calls is not None else []  # (pattern, file)

    def next_id(self) -> str:
        self.call_index += 1
        return f"{self.id_prefix}-{self.call_index:04d}"

    def visit_Call(self, node: ast.Call) -> None:
        target = _call_target_name(node)
        if not target:
            self.generic_visit(node)
            return

        chain = _get_call_chain(node)
        matched = _match_semantic_node(target, chain)

        # LLM inference: record (pattern, file) for deduplication, no per-call finding
        llm_pattern = _is_llm_inference_call(target, chain)
        if llm_pattern:
            self.llm_calls.append((llm_pattern, self.file_path))

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

        if any(p in target.lower() for p in AGENT_PATTERNS) and matched and matched[0] == "agent_orchestrator":
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


def _build_flow_from_hits(
    hits: List[_SemanticHit],
    flow_type: str,
    example_files: Optional[List[str]] = None,
    occurrence_count: int = 1,
) -> DataFlowGraph:
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
        example_files=example_files or [],
        occurrence_count=occurrence_count,
    )


def _cluster_flows(all_hits: List[Tuple[str, List[_SemanticHit]]]) -> List[DataFlowGraph]:
    """
    Cluster flows by semantic signature (which node types appear).
    Consolidate to one diagram per unique flow_type + node structure,
    with example files and occurrence count.
    """
    clusters: Dict[FrozenSet[str], List[Tuple[str, List[_SemanticHit]]]] = {}

    for file_path, hits in all_hits:
        if not hits:
            continue
        kinds = frozenset(h.kind for h in hits)
        if kinds not in clusters:
            clusters[kinds] = []
        clusters[kinds].append((file_path, hits))

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
        return "Other AI Pattern"

    result: List[DataFlowGraph] = []
    for kinds, file_hit_list in clusters.items():
        merged: List[_SemanticHit] = []
        example_files: List[str] = []
        for file_path, hits in file_hit_list:
            merged.extend(hits)
            if file_path not in example_files and len(example_files) < 3:
                example_files.append(file_path)
        flow_type = flow_type_name(kinds)
        count = len(file_hit_list)
        graph = _build_flow_from_hits(
            merged,
            flow_type,
            example_files=example_files,
            occurrence_count=count,
        )
        if graph.nodes:
            result.append(graph)

    # Sort: RAG first, then AI Agents, Embedding Pipeline, Direct LLM, Other
    priority = {"RAG": 0, "AI Agents": 1, "Embedding Pipeline": 2, "Direct LLM": 3}
    result.sort(key=lambda g: (priority.get(g.flow_type or "", 4), -g.occurrence_count))
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

    llm_calls: List[Tuple[str, str]] = []  # (pattern, file)

    for path in repo_root.rglob("*.py"):
        if _should_skip_path(path, repo_root):
            continue

        try:
            source = path.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(source, filename=str(path))
        except (SyntaxError, OSError):
            continue

        rel_path = str(path.relative_to(repo_root))
        visitor = _SemanticFlowVisitor(rel_path, findings, id_prefix="SEM", llm_calls=llm_calls)
        visitor.visit(tree)

        if visitor.hits:
            all_hits.append((rel_path, visitor.hits))

    # Aggregate LLM calls into deduplicated patterns
    by_pattern: Dict[str, List[str]] = defaultdict(list)
    for pattern, file_path in llm_calls:
        by_pattern[pattern].append(file_path)

    llm_usage: Dict[str, LLMPatternUsage] = {}
    for pattern, files_list in by_pattern.items():
        llm_usage[pattern] = LLMPatternUsage(
            pattern=pattern,
            call_sites=len(files_list),
            files=sorted(set(files_list)),
            provider=_infer_provider_from_pattern(pattern),
        )

    # One summary finding for LLM inference (for risk scoring has_inference)
    if llm_usage:
        total_sites = sum(u.call_sites for u in llm_usage.values())
        findings.append(
            Finding(
                id="SEM0000",
                title=f"LLM inference detected ({len(llm_usage)} patterns, {total_sites} call sites)",
                category=FindingCategory.SEMANTIC,
                severity=Severity.MEDIUM,
                description=f"Deduplicated LLM invocation: {len(llm_usage)} patterns, {total_sites} total call sites.",
                evidence=[],
                tags=["semantic-flow", "inference-call", "llm-deduplicated"],
            )
        )

    dataflows = _cluster_flows(all_hits)
    return SemanticDiscoveryResult(
        dataflows=dataflows,
        findings=findings,
        llm_usage=llm_usage,
    )
