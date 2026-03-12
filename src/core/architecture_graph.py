"""
AI Architecture Graph builder.

Builds a unified graph from AIBOM, DataFlowAnalysisResult, SemanticDiscoveryResult,
and ArchitectureResult. Uses dict/list representation (no networkx dependency).
Exports to JSON and Mermaid.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import AIBOM, DataFlowGraph


# Node kinds for the architecture graph
NODE_KINDS = frozenset({
    "user_input", "api_endpoint", "document_loader", "embedding_model",
    "vector_db", "retriever", "llm_provider", "agent", "tool", "database",
    "model_artifact",
})


def _node_id(kind: str, label: str) -> str:
    """Generate a safe node ID for the graph."""
    base = f"{kind}_{label}"[:50].replace(" ", "_").replace(".", "_")
    return "".join(c for c in base if c.isalnum() or c == "_") or f"{kind}_0"


def _edge(source: str, target: str, label: Optional[str] = None) -> Dict[str, Any]:
    return {"source": source, "target": target, "label": label}


def build_architecture_graph(
    aibom: AIBOM,
    dataflow_analysis: Optional[Any] = None,
    semantic_result: Optional[Any] = None,
    architecture_result: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    Build unified AI architecture graph from discovery and analysis results.

    Returns dict with keys: nodes, edges
    Each node: {id, kind, label, file?, line?}
    Each edge: {source, target, label?}
    """
    nodes: Dict[str, Dict[str, Any]] = {}
    edges: List[Dict[str, Any]] = []

    def add_node(nid: str, kind: str, label: str, file: Optional[str] = None, line: Optional[int] = None) -> str:
        if nid not in nodes:
            nodes[nid] = {"id": nid, "kind": kind, "label": label}
            if file:
                nodes[nid]["file"] = file
            if line is not None:
                nodes[nid]["line"] = line
        return nid

    def add_edge(src: str, tgt: str, lbl: Optional[str] = None) -> None:
        edges.append(_edge(src, tgt, lbl))

    # 1. From dataflow analysis: user_input → llm_provider
    if dataflow_analysis and getattr(dataflow_analysis, "data_flows", None):
        for df in dataflow_analysis.data_flows:
            src_id = _node_id("user_input", df.source)
            add_node(src_id, "user_input", df.source, df.file, df.line)
            sink_label = df.sink[:40] if df.sink else "llm"
            tgt_id = _node_id("llm_provider", sink_label)
            add_node(tgt_id, "llm_provider", sink_label)
            add_edge(src_id, tgt_id, df.source)

    # 2. From semantic dataflows (DataFlowGraph)
    if aibom and aibom.dataflows:
        for dg in aibom.dataflows:
            for node in dg.nodes:
                nid = node.id if node.id else _node_id(node.kind, node.label)
                add_node(nid, node.kind, node.label)
            prev_id = None
            for node in dg.nodes:
                nid = node.id if node.id else _node_id(node.kind, node.label)
                if prev_id:
                    add_edge(prev_id, nid, dg.flow_type)
                prev_id = nid
            for edge in dg.edges:
                if edge.source and edge.target:
                    add_edge(edge.source, edge.target, edge.label)

    # 3. From architecture inference (RAG, agents, etc.)
    arch = architecture_result
    if arch and getattr(arch, "detector_results", None):
        for dr in arch.detector_results:
            comp = dr.get("component", "")
            details = dr.get("details", {})
            if comp == "RAG":
                for emb in details.get("embeddings", [])[:2]:
                    nid = add_node(_node_id("embedding_model", emb), "embedding_model", emb)
                    vdb_id = _node_id("vector_db", "vector_store")
                    add_node(vdb_id, "vector_db", "vector_store")
                    add_edge(nid, vdb_id)
                for vs in details.get("vector_stores", [])[:2]:
                    nid = add_node(_node_id("vector_db", vs), "vector_db", vs)
                    ret_id = add_node(_node_id("retriever", "retriever"), "retriever", "retriever")
                    add_edge(nid, ret_id)
                for loader in details.get("document_loaders", [])[:2]:
                    nid = add_node(_node_id("document_loader", loader), "document_loader", loader)
                    emb_id = add_node(_node_id("embedding_model", "embedding"), "embedding_model", "embedding")
                    add_edge(nid, emb_id)
            elif "RAG" in comp or "Agent" in comp:
                ag_id = add_node(_node_id("agent", comp), "agent", comp)
                llm_id = add_node(_node_id("llm_provider", "llm"), "llm_provider", "LLM")
                add_edge(ag_id, llm_id)

    # 4. Model artifacts from AIBOM
    if aibom and aibom.models:
        for m in aibom.models[:5]:
            nid = add_node(_node_id("model_artifact", m.name), "model_artifact", m.name)
            # Connect to embedding if path suggests embedding model
            if "embed" in m.name.lower() or "encoder" in m.name.lower():
                emb_id = add_node(_node_id("embedding_model", m.name), "embedding_model", m.name)
                add_edge(nid, emb_id)

    return {
        "nodes": list(nodes.values()),
        "edges": edges,
    }


def architecture_graph_to_json(graph: Dict[str, Any]) -> str:
    """Export graph to JSON string."""
    import json
    return json.dumps(graph, indent=2)


def architecture_graph_to_mermaid(graph: Dict[str, Any], layout: str = "LR") -> str:
    """Export graph to Mermaid flowchart."""
    direction = layout.upper() if layout in ("LR", "TD", "BT", "RL") else "LR"
    lines = [f"flowchart {direction}"]
    node_map = {n["id"]: n for n in graph.get("nodes", [])}
    for n in graph.get("nodes", []):
        nid = n["id"]
        label = n.get("label", nid).replace('"', "&quot;")
        lines.append(f'  {nid}(["{label}"])')
    for e in graph.get("edges", []):
        src, tgt = e.get("source"), e.get("target")
        if src in node_map and tgt in node_map:
            lbl = e.get("label")
            if lbl:
                lines.append(f"  {src} -->|{lbl[:20]}| {tgt}")
            else:
                lines.append(f"  {src} --> {tgt}")
    return "\n".join(lines)
