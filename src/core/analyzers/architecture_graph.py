"""
Evidence-backed AI architecture graph.

Nodes are components observed in source (call sites, route functions, MCP
config). Edges are observed calls or argument passing — not package
co-occurrence, not taint confirmation, and not sequential semantic clustering.
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

_HOP_ARG = re.compile(
    r"^(?P<sfile>.+?)::(?P<sfunc>\S+)\s+arg\s+->\s+"
    r"(?P<tfile>.+?)::(?P<tfunc>\S+)\s+param\s+(?P<param>\S+)$"
)

from ..models import AIBOM
from ..utils.ast_utils import get_call_chain, walk_python_files
from .dataflow_analyzer import _is_sink_call
from .taint_catalog import (
    RAG_INGEST_ATTRS,
    RETRIEVAL_ATTRS,
    call_attr,
    is_http_client_call,
    is_http_factory_call,
    is_sql_execute_call,
    is_sql_factory_call,
)

NODE_KINDS = frozenset({
    "api_endpoint",
    "agent",
    "prompt_builder",
    "llm_provider",
    "embedding_model",
    "vector_db",
    "retriever",
    "memory",
    "tool",
    "mcp_server",
    "database",
    "http_client",
    "security_control",
    "function",
})

_ROUTE_DECORATORS = {
    "get", "post", "put", "delete", "patch", "route", "api_route", "websocket",
}
_PROMPT_CTOR = {
    "chatprompttemplate", "prompttemplate", "systemmessageprompttemplate",
    "humanmessageprompttemplate",
}
_PROMPT_ATTR = {"from_template", "from_messages", "format_messages", "format_prompt"}
_EMBED_CTOR = {
    "openaiembeddings", "cohereembeddings", "voyageembeddings",
    "huggingfaceembeddings", "vertexaiembeddings", "bedrockembeddings",
}
_EMBED_ATTR = {"embed_query", "embed_documents", "embed_text", "get_embedding"}
_VS_CTOR = {
    "chroma", "chromavectorstore", "pinecone", "pineconevectorstore",
    "weaviate", "weaviatevectorstore", "qdrant", "qdrantclient",
    "qdrantvectorstore", "faiss", "faissvectorstore", "pgvector", "milvus",
}
_VS_CHAIN = {"chroma", "chromadb", "pinecone", "weaviate", "qdrant", "faiss", "milvus", "pgvector"}
_AGENT_CALLS = {
    "create_react_agent", "create_agent", "initialize_agent", "agentexecutor",
    "stategraph", "create_crew", "assistantagent", "userproxyagent",
    "conversableagent",
}
_MEMORY_CTOR = {
    "conversationbuffermemory", "conversationsummarymemory",
    "chatmessagehistory", "redischatmessagehistory",
}
_TOOL_CTOR = {"tool", "structuredtool", "pythonrepltool", "basetool"}
_GUARD_HINTS = {"guardrails", "nemoguardrails", "llm_guard", "presidio", "rebuff"}
_MAX_NODES = 120
_MAX_EDGES = 180


def _safe_id(*parts: Any) -> str:
    """Stable mermaid-safe identifier."""
    raw = "_".join(str(p) for p in parts if p is not None)
    chars = []
    for ch in raw:
        chars.append(ch if ch.isalnum() else "_")
    out = "".join(chars)
    while "__" in out:
        out = out.replace("__", "_")
    return (out.strip("_") or "n")[:80]


def _import_modules(tree: ast.AST) -> Dict[str, str]:
    """Map local import names to module paths."""
    out: Dict[str, str] = {}
    for node in getattr(tree, "body", []):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name.split(".")[0]
                out[local] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                if alias.name == "*":
                    continue
                out[alias.asname or alias.name] = node.module
    return out


def _decorator_attrs(func: ast.AST) -> List[str]:
    names: List[str] = []
    for d in getattr(func, "decorator_list", []) or []:
        if isinstance(d, ast.Name):
            names.append(d.id.lower())
        elif isinstance(d, ast.Attribute):
            names.append(d.attr.lower())
        elif isinstance(d, ast.Call):
            if isinstance(d.func, ast.Attribute):
                names.append(d.func.attr.lower())
            elif isinstance(d.func, ast.Name):
                names.append(d.func.id.lower())
    return names


def _is_route(func: ast.AST) -> bool:
    return any(n in _ROUTE_DECORATORS for n in _decorator_attrs(func))


def _chain_set(node: ast.Call) -> Set[str]:
    return {c.lower() for c in get_call_chain(node)}


def _classify_call(
    node: ast.Call,
    import_modules: Dict[str, str],
    sql_receivers: Set[str],
    http_receivers: Set[str],
    bindings: Dict[str, str],
) -> Optional[Tuple[str, str]]:
    """Return (kind, display_label) for an observed Call, or None."""
    attr = call_attr(node)
    chain = get_call_chain(node)
    chain_l = [c.lower() for c in chain]
    parts = set(chain_l)
    label = ".".join(chain[-3:]) if chain else (attr or "call")

    llm = _is_sink_call(node, import_modules=import_modules)
    if llm:
        return "llm_provider", llm

    head = chain_l[0] if chain_l else ""
    bound = bindings.get(head, "")

    if attr in _PROMPT_ATTR or any(c in _PROMPT_CTOR for c in chain_l):
        return "prompt_builder", label
    if attr in _EMBED_ATTR or any(c in _EMBED_CTOR for c in chain_l):
        return "embedding_model", label
    if attr == "as_retriever" or attr in RETRIEVAL_ATTRS:
        if bound == "vector_db" or parts & _VS_CHAIN or attr in RETRIEVAL_ATTRS:
            kind = "retriever" if attr == "as_retriever" or attr in RETRIEVAL_ATTRS else "vector_db"
            if attr in RAG_INGEST_ATTRS and (bound == "vector_db" or parts & _VS_CHAIN):
                return "vector_db", label
            return kind, label
    if attr in RAG_INGEST_ATTRS and (bound == "vector_db" or parts & _VS_CHAIN):
        return "vector_db", label
    if any(c in _VS_CTOR for c in chain_l) or (
        attr in {"from_documents", "from_texts"} and (parts & _VS_CHAIN or bound == "vector_db")
    ):
        return "vector_db", label
    if any(c in _AGENT_CALLS for c in chain_l) or attr in _AGENT_CALLS:
        return "agent", label
    if any(c in _MEMORY_CTOR for c in chain_l):
        return "memory", label
    if any(c in _TOOL_CTOR for c in chain_l) or (
        attr == "from_function" and "tool" in parts
    ):
        return "tool", label
    if any(h in ".".join(chain_l) for h in _GUARD_HINTS):
        return "security_control", label
    if is_http_client_call(node, import_modules, http_receivers):
        return "http_client", label
    if is_sql_execute_call(node, sql_receivers):
        return "database", label
    return None


def _os_rce(node: ast.Call) -> bool:
    attr = call_attr(node)
    parts = _chain_set(node)
    return attr in {"system", "popen"} and "os" in parts


def _assign_names(node: ast.Assign) -> List[str]:
    names: List[str] = []
    for t in node.targets:
        if isinstance(t, ast.Name):
            names.append(t.id.lower())
    return names


def build_architecture_graph(
    aibom: AIBOM,
    dataflow_analysis: Optional[Any] = None,
    semantic_result: Optional[Any] = None,
    architecture_result: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    Build an architecture graph from observed calls and MCP config.

    Does not copy DataFlow taint into architecture edges. Semantic AIBOM
    flow patterns are not converted into observed edges (they order hits
    by type, which is not a call).
    """
    nodes: Dict[str, Dict[str, Any]] = {}
    edges: List[Dict[str, Any]] = []
    edge_seen: Set[Tuple[str, str, str]] = set()
    file_funcs: Dict[str, Dict[str, str]] = {}

    def add_node(
        nid: str,
        kind: str,
        label: str,
        *,
        file: Optional[str] = None,
        line: Optional[int] = None,
        evidence: str = "",
        method: str = "ast_call",
        confidence: str = "high",
    ) -> str:
        if len(nodes) >= _MAX_NODES and nid not in nodes:
            return nid
        if nid not in nodes:
            rec: Dict[str, Any] = {
                "id": nid,
                "kind": kind,
                "label": label,
                "evidence": evidence,
                "detection_method": method,
                "confidence": confidence,
                "evidence_status": "observed",
            }
            if file:
                rec["file"] = file
            if line is not None and int(line) > 0:
                rec["line"] = int(line)
            nodes[nid] = rec
        elif file and "file" not in nodes[nid]:
            nodes[nid]["file"] = file
        return nid

    def add_edge(
        src: str,
        tgt: str,
        rel: str,
        *,
        evidence: str = "",
        status: str = "observed",
        file: Optional[str] = None,
        line: Optional[int] = None,
    ) -> None:
        if src not in nodes or tgt not in nodes or src == tgt:
            return
        key = (src, tgt, rel)
        if key in edge_seen or len(edges) >= _MAX_EDGES:
            return
        edge_seen.add(key)
        rec: Dict[str, Any] = {
            "source": src,
            "target": tgt,
            "label": rel,
            "relationship": rel,
            "evidence": evidence,
            "evidence_status": status,
        }
        if file:
            rec["file"] = file
        if line is not None and int(line) > 0:
            rec["line"] = int(line)
        edges.append(rec)

    repo = Path(getattr(aibom, "repo_path", ".") or ".")
    try:
        files = walk_python_files(repo) if repo.exists() else []
    except Exception:
        files = []

    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(text)
        except (SyntaxError, OSError, ValueError):
            continue
        try:
            rel = str(path.relative_to(repo.resolve()))
        except Exception:
            rel = path.name
        im = _import_modules(tree)
        funcs_here: Dict[str, str] = {}
        for node in getattr(tree, "body", []):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                fid = _safe_id("fn", rel, node.name)
                funcs_here[node.name] = fid
                kind = "api_endpoint" if _is_route(node) else "function"
                add_node(
                    fid,
                    kind,
                    f"{rel.split('/')[-1]}::{node.name}",
                    file=rel,
                    line=getattr(node, "lineno", None),
                    evidence=f"{'route decorator' if kind == 'api_endpoint' else 'function definition'} at {rel}:{getattr(node, 'lineno', None)}",
                    method="ast_function",
                )
            elif isinstance(node, ast.ClassDef):
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        qname = f"{node.name}.{item.name}"
                        fid = _safe_id("fn", rel, qname)
                        funcs_here[qname] = fid
                        funcs_here[item.name] = funcs_here.get(item.name, fid)
                        add_node(
                            fid,
                            "function",
                            f"{rel.split('/')[-1]}::{qname}",
                            file=rel,
                            line=getattr(item, "lineno", None),
                            evidence=f"method definition at {rel}:{getattr(item, 'lineno', None)}",
                            method="ast_function",
                        )
        file_funcs[rel] = funcs_here

        class _Visitor(ast.NodeVisitor):
            def __init__(self) -> None:
                self.func_stack: List[str] = []
                self.bindings: Dict[str, str] = {}
                self.sql_receivers: Set[str] = set()
                self.http_receivers: Set[str] = set()

            def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
                self._enter_func(node)

            def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
                self._enter_func(node)

            def _enter_func(self, node: ast.AST) -> None:
                name = getattr(node, "name", "")
                fid = funcs_here.get(name) or _safe_id("fn", rel, name)
                self.func_stack.append(fid)
                prev_bind = dict(self.bindings)
                self.generic_visit(node)
                self.bindings = prev_bind
                self.func_stack.pop()

            def visit_Assign(self, node: ast.Assign) -> None:
                if isinstance(node.value, ast.Call):
                    if is_sql_factory_call(node.value):
                        self.sql_receivers.update(_assign_names(node))
                    if is_http_factory_call(node.value, im):
                        self.http_receivers.update(_assign_names(node))
                    classified = _classify_call(
                        node.value, im, self.sql_receivers, self.http_receivers, self.bindings,
                    )
                    if classified:
                        kind, _ = classified
                        for n in _assign_names(node):
                            self.bindings[n] = kind
                self.generic_visit(node)

            def visit_Call(self, node: ast.Call) -> None:
                lineno = getattr(node, "lineno", None)
                caller = self.func_stack[-1] if self.func_stack else ""
                classified = _classify_call(
                    node, im, self.sql_receivers, self.http_receivers, self.bindings,
                )
                if _os_rce(node):
                    classified = ("tool", "os.system")
                if classified and caller:
                    kind, label = classified
                    cid = _safe_id(kind, rel, nodes.get(caller, {}).get("label", caller).split("::")[-1])
                    add_node(
                        cid,
                        kind,
                        label,
                        file=rel,
                        line=lineno,
                        evidence=f"call {label} at {rel}:{lineno}",
                    )
                    add_edge(
                        caller,
                        cid,
                        "invokes",
                        evidence=f"{rel}:{lineno} {label}",
                        file=rel,
                        line=lineno,
                    )
                    if kind == "retriever":
                        recv = get_call_chain(node)
                        head = recv[0].lower() if recv else ""
                        if self.bindings.get(head) == "vector_db":
                            vs_id = _safe_id("vector_db", rel, nodes.get(caller, {}).get("label", caller).split("::")[-1])
                            if vs_id in nodes:
                                add_edge(
                                    cid,
                                    vs_id,
                                    "retrieves_from",
                                    evidence=f"{rel}:{lineno} {head}.{call_attr(node)}",
                                    file=rel,
                                    line=lineno,
                                )
                    arg_names: List[ast.Name] = [
                        a for a in node.args if isinstance(a, ast.Name)
                    ]
                    for kw in node.keywords:
                        if isinstance(kw.value, ast.Name):
                            arg_names.append(kw.value)
                    if classified[0] == "vector_db":
                        for nm in arg_names:
                            if self.bindings.get(nm.id.lower()) == "embedding_model":
                                emb_id = _safe_id(
                                    "embedding_model",
                                    rel,
                                    nodes.get(caller, {}).get("label", caller).split("::")[-1],
                                )
                                if emb_id in nodes:
                                    add_edge(
                                        emb_id,
                                        cid,
                                        "passed_to",
                                        evidence=f"{rel}:{lineno} embedding argument {nm.id}",
                                        file=rel,
                                        line=lineno,
                                    )
                chain = get_call_chain(node)
                if len(chain) == 1 and caller:
                    callee = funcs_here.get(chain[0])
                    if callee and callee != caller:
                        add_edge(
                            caller,
                            callee,
                            "calls",
                            evidence=f"{rel}:{lineno} {chain[0]}()",
                            file=rel,
                            line=lineno,
                        )
                self.generic_visit(node)

        try:
            _Visitor().visit(tree)
        except Exception:
            continue

    # MCP servers from config (not from package imports).
    if aibom is not None:
        for server in getattr(aibom, "mcp_servers", None) or []:
            sid = _safe_id("mcp", getattr(server, "id", None) or getattr(server, "name", "mcp"))
            add_node(
                sid,
                "mcp_server",
                getattr(server, "name", None) or sid,
                file=getattr(server, "config_path", None) or None,
                evidence=f"MCP config {getattr(server, 'config_path', '')}",
                method="mcp_config",
            )

    # Recorded argument hops are observed calls (not taint confirmation).
    if dataflow_analysis is not None:
        for df in getattr(dataflow_analysis, "data_flows", None) or []:
            for hop in getattr(df, "hops", None) or []:
                m = _HOP_ARG.match(str(hop).strip())
                if not m:
                    continue
                src = _safe_id("fn", m.group("sfile"), m.group("sfunc"))
                tgt = _safe_id("fn", m.group("tfile"), m.group("tfunc"))
                if src in nodes and tgt in nodes:
                    add_edge(
                        src,
                        tgt,
                        "calls",
                        evidence=(
                            f"recorded call {m.group('sfile')}::{m.group('sfunc')}"
                            f" -> {m.group('tfile')}::{m.group('tfunc')}"
                        ),
                        status="observed",
                    )

    # Drop isolated generic functions that never invoke an AI component.
    ai_kinds = NODE_KINDS - {"function"}
    connected = {e["source"] for e in edges} | {e["target"] for e in edges}
    interesting = {
        nid for nid, n in nodes.items()
        if n["kind"] in ai_kinds or nid in connected and n["kind"] == "api_endpoint"
    }
    keep = set(interesting)
    for e in edges:
        if e["source"] in interesting or e["target"] in interesting:
            keep.add(e["source"])
            keep.add(e["target"])
    # Keep MCP even if isolated — config evidence is enough to show the server.
    for nid, n in nodes.items():
        if n["kind"] == "mcp_server":
            keep.add(nid)
    nodes = {k: v for k, v in nodes.items() if k in keep}
    edges = [e for e in edges if e["source"] in nodes and e["target"] in nodes]

    observed = sum(1 for e in edges if e.get("evidence_status") == "observed")
    return {
        "nodes": list(nodes.values()),
        "edges": edges,
        "not_value_taint": True,
        "stats": {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "observed_edge_count": observed,
            "inferred_edge_count": len(edges) - observed,
        },
    }


def architecture_graph_to_json(graph: Dict[str, Any]) -> str:
    """Export graph to JSON string."""
    return json.dumps(graph, indent=2, default=str)


def architecture_graph_to_mermaid(graph: Dict[str, Any], layout: str = "LR") -> str:
    """Export graph to Mermaid flowchart."""
    direction = layout.upper() if layout in ("LR", "TD", "BT", "RL") else "LR"
    lines = [f"flowchart {direction}"]
    node_map = {n["id"]: n for n in graph.get("nodes", [])}
    for n in graph.get("nodes", []):
        nid = n["id"]
        label = str(n.get("label", nid)).replace('"', "&quot;")
        lines.append(f'  {nid}(["{label}"])')
    for e in graph.get("edges", []):
        src, tgt = e.get("source"), e.get("target")
        if src in node_map and tgt in node_map:
            lbl = e.get("label") or e.get("relationship") or ""
            if lbl:
                lines.append(f"  {src} -->|{str(lbl)[:20]}| {tgt}")
            else:
                lines.append(f"  {src} --> {tgt}")
    return "\n".join(lines)
