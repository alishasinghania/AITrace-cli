"""
Evidence-backed AI architecture graph.

Nodes are components observed in source (call sites, route functions, MCP
config). Edges are classified from evidence:

- DIRECT_CALL / FRAMEWORK_CALL: AST or framework invocation (solid, observed)
- STRUCTURAL: repository/module/component relationship (dashed)
- INFERRED: unresolved dynamic dispatch (dashed)

Construction, imports, registry membership, and object identity are not
treated as function invocation. DataFlow overlay marks sinks and confirmed
taint; architecture reachability is never taint confirmation.
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
    classify_sink,
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

EDGE_CLASSIFICATIONS = frozenset({
    "DIRECT_CALL",
    "FRAMEWORK_CALL",
    "STRUCTURAL",
    "INFERRED",
})

_CLASS_RANK = {
    "DIRECT_CALL": 0,
    "FRAMEWORK_CALL": 1,
    "STRUCTURAL": 2,
    "INFERRED": 3,
}

_OBSERVED_CLASSES = frozenset({"DIRECT_CALL", "FRAMEWORK_CALL"})

_ROUTE_DECORATORS = {
    "get", "post", "put", "delete", "patch", "route", "api_route", "websocket",
    "websocket_route", "options", "head",
}
_HTTP_METHODS = frozenset({
    "get", "post", "put", "delete", "patch", "options", "head",
})
_WS_DECORATORS = frozenset({"websocket", "websocket_route"})
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
_CONSTRUCTOR_ATTRS = {
    "from_template", "from_messages", "from_documents", "from_texts",
    "from_function", "as_retriever",
}
_FRAMEWORK_INVOKE_ATTRS = {
    "invoke", "ainvoke", "stream", "astream", "batch", "abatch",
    "run", "arun", "execute", "aexecute",
    "embed_query", "embed_documents", "embed_text", "get_embedding",
    "get_relevant_documents", "aget_relevant_documents",
    "similarity_search", "similarity_search_with_score",
    "format_messages", "format_prompt",
}
_CTOR_NAMES = _PROMPT_CTOR | _EMBED_CTOR | _VS_CTOR | _AGENT_CALLS | _MEMORY_CTOR | _TOOL_CTOR
# Result transforms are not architecture components (llm.invoke(...).strip()).
_NON_COMPONENT_ATTRS = {
    "strip", "lstrip", "rstrip", "lower", "upper", "split", "replace", "join",
    "format", "encode", "decode",
}
_SINK_KIND_DEFAULT = {
    "llm_provider": "llm",
    "database": "sql",
    "http_client": "network",
    "mcp_server": "mcp",
}
_SINK_CAT_MAP = {
    "llm": "llm",
    "sql": "sql",
    "rce": "rce",
    "http": "network",
    "email": "smtp",
    "filesystem": "filesystem",
    "file": "filesystem",
}
LAYER_API = "API"
LAYER_ORCH = "Orchestration"
LAYER_BIZ = "Business Logic / Agent Workflows"
LAYER_AGENTS = "Agents / Tools / Integrations"
LAYER_DATA = "Data Stores / Retrieval"
LAYER_EXT = "External Services / Security Sinks"
LAYER_ORDER: Tuple[str, ...] = (
    LAYER_API, LAYER_ORCH, LAYER_BIZ, LAYER_AGENTS, LAYER_DATA, LAYER_EXT,
)
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


def _const_str(node: ast.AST) -> Optional[str]:
    """String constant, or None."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _methods_from_ast(node: ast.AST) -> List[str]:
    """Parse Flask-style methods=['POST'] lists."""
    out: List[str] = []
    if isinstance(node, (ast.List, ast.Tuple)):
        for elt in node.elts:
            val = _const_str(elt)
            if val:
                out.append(val.upper())
    val = _const_str(node)
    if val:
        out.append(val.upper())
    return out


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


def _imported_symbols(tree: ast.AST) -> Dict[str, Tuple[str, Optional[str]]]:
    """Map local name to (module_path, original_symbol or None for module imports)."""
    out: Dict[str, Tuple[str, Optional[str]]] = {}
    for node in getattr(tree, "body", []):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name.split(".")[0]
                out[local] = (alias.name, None)
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                if alias.name == "*":
                    continue
                out[alias.asname or alias.name] = (node.module, alias.name)
    return out


def _rel_module(rel: str) -> str:
    """Convert a repo-relative path to a dotted module name."""
    p = rel.replace("\\", "/").replace("/", ".")
    if p.endswith(".py"):
        p = p[:-3]
    if p.endswith(".__init__"):
        p = p[:-9]
    return p


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


def _route_meta(func: ast.AST) -> Optional[Dict[str, Any]]:
    """HTTP method, path, and websocket flag from a route decorator Call."""
    for d in getattr(func, "decorator_list", []) or []:
        call = d if isinstance(d, ast.Call) else None
        attr = ""
        if isinstance(d, ast.Attribute):
            attr = d.attr.lower()
        elif isinstance(d, ast.Name):
            attr = d.id.lower()
        elif call is not None:
            if isinstance(call.func, ast.Attribute):
                attr = call.func.attr.lower()
            elif isinstance(call.func, ast.Name):
                attr = call.func.id.lower()
        if attr not in _ROUTE_DECORATORS:
            continue
        path = ""
        methods: List[str] = []
        websocket = attr in _WS_DECORATORS
        if call is not None:
            if call.args:
                path = _const_str(call.args[0]) or ""
            for kw in call.keywords:
                if kw.arg in {"path", "rule"}:
                    path = _const_str(kw.value) or path
                elif kw.arg == "methods":
                    methods = _methods_from_ast(kw.value)
        if attr in _HTTP_METHODS:
            methods = [attr.upper()]
        elif not methods and not websocket:
            methods = ["GET"]
        return {
            "route_path": path,
            "http_methods": methods,
            "websocket": websocket,
        }
    return None


def _is_route(func: ast.AST) -> bool:
    return any(n in _ROUTE_DECORATORS for n in _decorator_attrs(func))


def _chain_set(node: ast.Call) -> Set[str]:
    return {c.lower() for c in get_call_chain(node)}


def _is_construction_call(node: ast.Call) -> bool:
    """True for constructors/factories, not for invoke/execute on the product."""
    attr = call_attr(node)
    chain_l = [c.lower() for c in get_call_chain(node)]
    if attr in _FRAMEWORK_INVOKE_ATTRS:
        return False
    if attr in _CONSTRUCTOR_ATTRS:
        return True
    if any(c in _CTOR_NAMES for c in chain_l):
        return True
    return False


def _dynamic_dispatch(node: ast.Call) -> Optional[Tuple[str, Optional[str]]]:
    """Return (kind, constant_key) for getattr/subscript dispatch, else None."""
    func = node.func
    if isinstance(func, ast.Call):
        inner = func.func
        if isinstance(inner, ast.Name) and inner.id == "getattr":
            key = _const_str(func.args[1]) if len(func.args) >= 2 else None
            return "getattr", key
        if isinstance(inner, ast.Attribute) and inner.attr == "get":
            key = _const_str(func.args[0]) if func.args else None
            return "mapping_get", key
    if isinstance(func, ast.Subscript):
        sl = func.slice
        key = _const_str(sl)
        index_cls = getattr(ast, "Index", None)
        if key is None and index_cls is not None and isinstance(sl, index_cls):
            key = _const_str(getattr(sl, "value", sl))
        return "subscript", key
    return None


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


def _sink_tags(
    node: ast.Call,
    import_modules: Dict[str, str],
    sql_receivers: Set[str],
    http_receivers: Set[str],
) -> List[str]:
    """Map classify_sink tags onto architecture sink categories."""
    try:
        tags = classify_sink(
            node,
            sql_receivers=sql_receivers,
            import_modules=import_modules,
            http_receivers=http_receivers,
        )
    except Exception:
        return []
    out: List[str] = []
    for tag in tags:
        mapped = _SINK_CAT_MAP.get(tag, "")
        if mapped and mapped not in out:
            out.append(mapped)
    if _os_rce(node) and "rce" not in out:
        out.append("rce")
    return out


def _edge_status(classification: str) -> str:
    """evidence_status derived from classification. Never observed without evidence."""
    if classification in _OBSERVED_CLASSES:
        return "observed"
    if classification == "STRUCTURAL":
        return "structural"
    return "inferred"


def _resolved_callee(
    chain: List[str],
    funcs_here: Dict[str, str],
    symbols: Dict[str, Tuple[str, Optional[str]]],
    file_funcs: Dict[str, Dict[str, str]],
    module_files: Dict[str, str],
) -> Optional[str]:
    """Resolve a call chain to a function node id, or None if not evidence-backed."""
    if not chain:
        return None
    if len(chain) == 1:
        name = chain[0]
        if name in funcs_here:
            return funcs_here[name]
        spec = symbols.get(name)
        if spec:
            mod, orig = spec
            fname = orig or name
            fpath = module_files.get(mod)
            if fpath and fname in file_funcs.get(fpath, {}):
                return file_funcs[fpath][fname]
        return None
    if len(chain) == 2 and f"{chain[0]}.{chain[1]}" in funcs_here:
        return funcs_here[f"{chain[0]}.{chain[1]}"]
    head, attr = chain[0], chain[-1]
    spec = symbols.get(head)
    if spec and spec[1] is None:
        fpath = module_files.get(spec[0])
        if fpath and attr in file_funcs.get(fpath, {}):
            return file_funcs[fpath][attr]
    return None


def _qualified_call(node: ast.Call) -> str:
    """Last one or two names in a call chain, e.g. llm.invoke."""
    chain = get_call_chain(node)
    attr = call_attr(node) or "call"
    if len(chain) >= 2:
        return ".".join(chain[-2:])
    if chain:
        return chain[0]
    return attr


def _receiver_module(
    node: ast.Call,
    rel: str,
    symbols: Dict[str, Tuple[str, Optional[str]]],
    name_modules: Dict[str, str],
) -> str:
    """Module that owns the receiver, from imports/assignments; else the caller file."""
    chain = get_call_chain(node)
    if not chain:
        return _rel_module(rel)
    head = chain[0]
    if head in name_modules:
        return name_modules[head]
    spec = symbols.get(head)
    if spec:
        return spec[0]
    return _rel_module(rel)


def _identity_module(
    node: ast.Call,
    rel: str,
    symbols: Dict[str, Tuple[str, Optional[str]]],
    name_modules: Dict[str, str],
    module_files: Dict[str, str],
    *,
    construction: bool,
) -> str:
    """Module used in a component id.

    In-repo receivers (app.llm) are shared. Third-party receivers (smtplib)
    stay scoped to the calling module so distinct wrappers are not merged.
    """
    if construction:
        return _rel_module(rel)
    recv = _receiver_module(node, rel, symbols, name_modules)
    scanned = set(module_files.keys())
    if recv in scanned or any(recv == m or recv.startswith(m + ".") for m in scanned):
        return recv
    return _rel_module(rel)


def _component_nid(
    kind: str,
    node: ast.Call,
    rel: str,
    symbols: Dict[str, Tuple[str, Optional[str]]],
    name_modules: Dict[str, str],
    module_files: Dict[str, str],
    *,
    construction: bool,
) -> str:
    """Stable id: kind + defining module + qualified name."""
    qname = _qualified_call(node)
    mod = _identity_module(
        node, rel, symbols, name_modules, module_files, construction=construction,
    )
    return _safe_id(kind, mod, qname)


def _append_callsite(bag: List[Dict[str, Any]], site: Dict[str, Any]) -> None:
    """Add a unique file:line callsite to a node or edge."""
    key = (site.get("file"), site.get("line"), site.get("evidence"))
    for existing in bag:
        if (existing.get("file"), existing.get("line"), existing.get("evidence")) == key:
            return
    bag.append(site)


def _api_label(rel: str, name: str, meta: Optional[Dict[str, Any]]) -> str:
    """Human label for a route function: METHOD path, or file::name."""
    if not meta:
        return f"{rel.split('/')[-1]}::{name}"
    path = meta.get("route_path") or ""
    if meta.get("websocket"):
        return f"WS {path}" if path else f"{rel.split('/')[-1]}::{name}"
    methods = meta.get("http_methods") or []
    prefix = "/".join(methods) if methods else ""
    if prefix and path:
        return f"{prefix} {path}"
    if path:
        return path
    return f"{rel.split('/')[-1]}::{name}"


def build_architecture_graph(
    aibom: AIBOM,
    dataflow_analysis: Optional[Any] = None,
    semantic_result: Optional[Any] = None,
    architecture_result: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    Build an architecture graph from observed calls, route decorators, and MCP config.

    Does not copy DataFlow taint into architecture edges. Semantic AIBOM
    flow patterns are not converted into observed edges (they order hits
    by type, which is not a call). STRUCTURAL and INFERRED edges are never
    upgraded to observed without invocation evidence.
    """
    nodes: Dict[str, Dict[str, Any]] = {}
    edges: List[Dict[str, Any]] = []
    edge_index: Dict[Tuple[str, str], int] = {}
    file_funcs: Dict[str, Dict[str, str]] = {}
    parsed: List[Tuple[str, ast.AST, Dict[str, str], Dict[str, Tuple[str, Optional[str]]]]] = []

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
        extra: Optional[Dict[str, Any]] = None,
    ) -> str:
        if len(nodes) >= _MAX_NODES and nid not in nodes:
            return nid
        extra = dict(extra or {})
        if nid not in nodes:
            rec: Dict[str, Any] = {
                "id": nid,
                "kind": kind,
                "label": label,
                "evidence": evidence,
                "detection_method": method,
                "confidence": confidence,
                "evidence_status": "observed",
                "is_sink": False,
                "taint_confirmed": False,
                "component_type": kind,
                "qualified_name": extra.get("qualified_name") or label,
                "module": extra.get("module") or (_rel_module(file) if file else ""),
                "invocation_status": extra.get("invocation_status") or "observed",
                "taint_status": "not_a_sink",
                "sink_type": extra.get("sink_category") or extra.get("sink_type") or "",
                "source_file": file or "",
                "source_line": int(line) if line is not None and int(line) > 0 else None,
                "callsites": [],
            }
            if file:
                rec["file"] = file
            if line is not None and int(line) > 0:
                rec["line"] = int(line)
            rec.update({k: v for k, v in extra.items() if k not in rec or rec[k] in (None, "", [], False)})
            rec["kind"] = kind
            rec["component_type"] = kind
            nodes[nid] = rec
        else:
            if file and "file" not in nodes[nid]:
                nodes[nid]["file"] = file
            if extra:
                for k, v in extra.items():
                    if k not in nodes[nid] or nodes[nid][k] in (None, "", [], False):
                        nodes[nid][k] = v
        if file:
            _append_callsite(nodes[nid].setdefault("callsites", []), {
                "file": file,
                "line": int(line) if line is not None and int(line) > 0 else None,
                "evidence": evidence,
            })
        return nid

    def add_edge(
        src: str,
        tgt: str,
        rel: str,
        *,
        classification: str = "DIRECT_CALL",
        evidence: str = "",
        status: Optional[str] = None,
        file: Optional[str] = None,
        line: Optional[int] = None,
        caller: str = "",
        callee: str = "",
    ) -> None:
        if src not in nodes or tgt not in nodes or src == tgt:
            return
        cls = classification if classification in EDGE_CLASSIFICATIONS else "INFERRED"
        derived = _edge_status(cls)
        # Callers may pass status, but never allow observed without evidence class.
        if status == "observed" and cls not in _OBSERVED_CLASSES:
            derived = _edge_status(cls)
        elif status in {"structural", "inferred"} and cls in _OBSERVED_CLASSES:
            derived = "observed"
        site: Dict[str, Any] = {
            "file": file or "",
            "line": int(line) if line is not None and int(line) > 0 else None,
            "evidence": evidence,
            "caller": caller or src,
            "callee": callee or tgt,
        }
        rec: Dict[str, Any] = {
            "source": src,
            "target": tgt,
            "label": rel,
            "relationship": rel,
            "classification": cls,
            "evidence": evidence,
            "evidence_status": derived,
            "invocation_status": derived,
            "caller": caller or src,
            "callee": callee or tgt,
            "callsites": [site],
        }
        if file:
            rec["file"] = file
            rec["source_file"] = file
        if line is not None and int(line) > 0:
            rec["line"] = int(line)
            rec["source_line"] = int(line)
        key = (src, tgt, rel)
        if key in edge_index:
            existing = edges[edge_index[key]]
            _append_callsite(existing.setdefault("callsites", []), site)
            old_rank = _CLASS_RANK.get(existing.get("classification") or "INFERRED", 9)
            new_rank = _CLASS_RANK.get(cls, 9)
            # Stronger evidence may replace weaker. Never the reverse.
            if new_rank < old_rank:
                keep_sites = list(existing.get("callsites") or [])
                rec["callsites"] = keep_sites
                edges[edge_index[key]] = rec
            return
        if len(edges) >= _MAX_EDGES:
            return
        edge_index[key] = len(edges)
        edges.append(rec)

    repo = Path(getattr(aibom, "repo_path", ".") or ".")
    try:
        files = walk_python_files(repo) if repo.exists() else []
    except Exception:
        files = []
    files = sorted(files, key=lambda p: str(p).replace("\\", "/"))

    # Phase 1: index functions, routes, and module paths.
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(text)
        except (SyntaxError, OSError, ValueError):
            continue
        try:
            rel = str(path.relative_to(repo.resolve())).replace("\\", "/")
        except Exception:
            rel = path.name
        im = _import_modules(tree)
        symbols = _imported_symbols(tree)
        funcs_here: Dict[str, str] = {}
        for node in getattr(tree, "body", []):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                fid = _safe_id("fn", rel, node.name)
                funcs_here[node.name] = fid
                meta = _route_meta(node) if _is_route(node) else None
                kind = "api_endpoint" if meta or _is_route(node) else "function"
                extra = dict(meta) if meta else {}
                extra.update({
                    "qualified_name": node.name,
                    "module": _rel_module(rel),
                    "component_type": kind,
                })
                add_node(
                    fid,
                    kind,
                    _api_label(rel, node.name, meta),
                    file=rel,
                    line=getattr(node, "lineno", None),
                    evidence=(
                        f"route decorator {meta.get('http_methods') or ('WS',)} "
                        f"{meta.get('route_path') or ''} at {rel}:{getattr(node, 'lineno', None)}"
                        if kind == "api_endpoint"
                        else f"function definition at {rel}:{getattr(node, 'lineno', None)}"
                    ),
                    method="ast_function",
                    extra=extra,
                )
            elif isinstance(node, ast.ClassDef):
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        qname = f"{node.name}.{item.name}"
                        fid = _safe_id("fn", rel, qname)
                        funcs_here[qname] = fid
                        funcs_here[item.name] = funcs_here.get(item.name, fid)
                        meta = _route_meta(item) if _is_route(item) else None
                        kind = "api_endpoint" if meta or _is_route(item) else "function"
                        extra = dict(meta) if meta else {}
                        extra.update({
                            "qualified_name": qname,
                            "module": _rel_module(rel),
                            "component_type": kind,
                        })
                        add_node(
                            fid,
                            kind,
                            _api_label(rel, qname, meta),
                            file=rel,
                            line=getattr(item, "lineno", None),
                            evidence=(
                                f"route method at {rel}:{getattr(item, 'lineno', None)}"
                                if kind == "api_endpoint"
                                else f"method definition at {rel}:{getattr(item, 'lineno', None)}"
                            ),
                            method="ast_function",
                            extra=extra,
                        )
        file_funcs[rel] = funcs_here
        parsed.append((rel, tree, im, symbols))

    module_files: Dict[str, str] = {}
    for rel in file_funcs:
        module_files[_rel_module(rel)] = rel

    # Phase 2: observed calls, construction, and (un)resolved dispatch.
    for rel, tree, im, symbols in parsed:
        funcs_here = file_funcs.get(rel, {})

        class _Visitor(ast.NodeVisitor):
            def __init__(self) -> None:
                self.func_stack: List[str] = []
                self.bindings: Dict[str, str] = {}
                self.name_modules: Dict[str, str] = {}
                self.last_id_by_kind: Dict[str, str] = {}
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
                prev_last = dict(self.last_id_by_kind)
                self.generic_visit(node)
                self.bindings = prev_bind
                self.last_id_by_kind = prev_last
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
                    chain = get_call_chain(node.value)
                    if chain:
                        spec = symbols.get(chain[0])
                        if spec:
                            for n in _assign_names(node):
                                self.name_modules[n] = spec[0]
                self.generic_visit(node)

            def visit_Call(self, node: ast.Call) -> None:
                lineno = getattr(node, "lineno", None)
                caller = self.func_stack[-1] if self.func_stack else ""
                classified = _classify_call(
                    node, im, self.sql_receivers, self.http_receivers, self.bindings,
                )
                if call_attr(node) in _NON_COMPONENT_ATTRS:
                    classified = None
                if _os_rce(node):
                    classified = ("tool", "os.system")
                tags = _sink_tags(node, im, self.sql_receivers, self.http_receivers)
                if classified is None and "smtp" in tags:
                    chain = get_call_chain(node)
                    classified = ("tool", ".".join(chain[-3:]) if chain else "smtp")
                dyn = _dynamic_dispatch(node)
                if dyn and caller:
                    _kind, key = dyn
                    resolved = None
                    if key:
                        resolved = _resolved_callee(
                            [key], funcs_here, symbols, file_funcs, module_files,
                        )
                    if resolved and resolved != caller:
                        add_edge(
                            caller,
                            resolved,
                            "calls",
                            classification="DIRECT_CALL",
                            evidence=f"{rel}:{lineno} resolved {dyn[0]} {key}()",
                            file=rel,
                            line=lineno,
                            caller=caller,
                            callee=resolved,
                        )
                    else:
                        did = _safe_id("dyn", rel, str(lineno or 0))
                        add_node(
                            did,
                            "function",
                            f"dynamic {dyn[0]}",
                            file=rel,
                            line=lineno,
                            evidence=f"unresolved {dyn[0]} at {rel}:{lineno}",
                            method="dynamic_dispatch",
                            confidence="low",
                            extra={"evidence_status": "inferred"},
                        )
                        add_edge(
                            caller,
                            did,
                            "inferred",
                            classification="INFERRED",
                            evidence=f"{rel}:{lineno} unresolved {dyn[0]}",
                            file=rel,
                            line=lineno,
                            caller=caller,
                            callee=did,
                        )
                    self.generic_visit(node)
                    return
                chain = get_call_chain(node)
                resolved = _resolved_callee(
                    chain, funcs_here, symbols, file_funcs, module_files,
                ) if caller else None
                if classified and caller:
                    kind, label = classified
                    # In-repo function calls already get a DIRECT_CALL edge. Do not
                    # also invent a parallel retriever/tool node for the same Call.
                    skip_classified = bool(resolved) and kind in {
                        "retriever", "tool", "function", "prompt_builder",
                    }
                    construction = _is_construction_call(node)
                    if not skip_classified:
                        cid = _component_nid(
                            kind, node, rel, symbols, self.name_modules, module_files,
                            construction=construction,
                        )
                        if construction:
                            cls = "STRUCTURAL"
                            rel_name = "constructs"
                        elif kind == "tool" and ("os.system" in label or "rce" in tags):
                            cls = "DIRECT_CALL"
                            rel_name = "invokes"
                        elif (
                            kind in {"llm_provider", "http_client", "database"}
                            or call_attr(node) in _FRAMEWORK_INVOKE_ATTRS
                        ):
                            cls = "FRAMEWORK_CALL"
                            rel_name = "invokes"
                        else:
                            cls = "FRAMEWORK_CALL"
                            rel_name = "invokes"
                        sink_cat = tags[0] if tags else _SINK_KIND_DEFAULT.get(kind, "")
                        extra = {
                            "qualified_name": _qualified_call(node),
                            "module": _identity_module(
                                node, rel, symbols, self.name_modules, module_files,
                                construction=construction,
                            ),
                            "component_type": kind,
                        }
                        if sink_cat:
                            extra["is_sink"] = True
                            extra["sink_category"] = sink_cat
                            extra["sink_type"] = sink_cat
                        add_node(
                            cid,
                            kind,
                            label,
                            file=rel,
                            line=lineno,
                            evidence=f"{'constructed' if construction else 'call'} {label} at {rel}:{lineno}",
                            extra=extra,
                        )
                        self.last_id_by_kind[kind] = cid
                        add_edge(
                            caller,
                            cid,
                            rel_name,
                            classification=cls,
                            evidence=f"{rel}:{lineno} {label}",
                            file=rel,
                            line=lineno,
                            caller=caller,
                            callee=cid,
                        )
                        if kind == "retriever":
                            recv = get_call_chain(node)
                            head = recv[0].lower() if recv else ""
                            vs_id = self.last_id_by_kind.get("vector_db")
                            if vs_id and vs_id in nodes and self.bindings.get(head) == "vector_db":
                                add_edge(
                                    cid,
                                    vs_id,
                                    "retrieves_from",
                                    classification="STRUCTURAL",
                                    evidence=f"{rel}:{lineno} {head}.{call_attr(node)}",
                                    file=rel,
                                    line=lineno,
                                    caller=cid,
                                    callee=vs_id,
                                )
                        arg_names: List[ast.Name] = [
                            a for a in node.args if isinstance(a, ast.Name)
                        ]
                        for kw in node.keywords:
                            if isinstance(kw.value, ast.Name):
                                arg_names.append(kw.value)
                        if classified[0] == "vector_db":
                            emb_id = self.last_id_by_kind.get("embedding_model")
                            for nm in arg_names:
                                if self.bindings.get(nm.id.lower()) == "embedding_model" and emb_id in nodes:
                                    add_edge(
                                        emb_id,
                                        cid,
                                        "passed_to",
                                        classification="STRUCTURAL",
                                        evidence=f"{rel}:{lineno} embedding argument {nm.id}",
                                        file=rel,
                                        line=lineno,
                                        caller=emb_id,
                                        callee=cid,
                                    )
                if resolved and caller and resolved != caller:
                    add_edge(
                        caller,
                        resolved,
                        "calls",
                        classification="DIRECT_CALL",
                        evidence=f"{rel}:{lineno} {'.'.join(chain)}()",
                        file=rel,
                        line=lineno,
                        caller=caller,
                        callee=resolved,
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
                extra={"is_sink": True, "sink_category": "mcp", "taint_confirmed": False},
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
                        classification="DIRECT_CALL",
                        evidence=(
                            f"recorded call {m.group('sfile')}::{m.group('sfunc')}"
                            f" -> {m.group('tfile')}::{m.group('tfunc')}"
                        ),
                        file=m.group("sfile"),
                        caller=src,
                        callee=tgt,
                    )

    _overlay_sinks(nodes, edges, dataflow_analysis)
    _assign_layers(nodes, edges)
    _finalize_security_fields(nodes, edges)

    # Drop isolated generic functions that never invoke an AI component.
    ai_kinds = NODE_KINDS - {"function"}
    connected = {e["source"] for e in edges} | {e["target"] for e in edges}
    interesting = {
        nid for nid, n in nodes.items()
        if n["kind"] in ai_kinds or (nid in connected and n["kind"] == "api_endpoint")
    }
    keep = set(interesting)
    for e in edges:
        if e["source"] in interesting or e["target"] in interesting:
            keep.add(e["source"])
            keep.add(e["target"])
    for nid, n in nodes.items():
        if n["kind"] == "mcp_server":
            keep.add(nid)
        if n.get("is_sink"):
            keep.add(nid)
    nodes = {k: v for k, v in nodes.items() if k in keep}
    edges = [e for e in edges if e["source"] in nodes and e["target"] in nodes]

    node_list = sorted(
        nodes.values(),
        key=lambda n: (
            str(n.get("kind") or ""),
            str(n.get("file") or ""),
            int(n.get("line") or 0),
            str(n.get("id") or ""),
        ),
    )
    edges_sorted = sorted(
        edges,
        key=lambda e: (
            str(e.get("source") or ""),
            str(e.get("target") or ""),
            str(e.get("classification") or ""),
            str(e.get("relationship") or ""),
        ),
    )
    observed = sum(1 for e in edges_sorted if e.get("evidence_status") == "observed")
    structural = sum(1 for e in edges_sorted if e.get("classification") == "STRUCTURAL")
    inferred = sum(1 for e in edges_sorted if e.get("classification") == "INFERRED")
    return {
        "nodes": node_list,
        "edges": edges_sorted,
        "not_value_taint": True,
        "stats": {
            "node_count": len(node_list),
            "edge_count": len(edges_sorted),
            "observed_edge_count": observed,
            "inferred_edge_count": len(edges_sorted) - observed,
            "structural_edge_count": structural,
            "inferred_classified_edge_count": inferred,
            "direct_call_count": sum(
                1 for e in edges_sorted if e.get("classification") == "DIRECT_CALL"
            ),
            "framework_call_count": sum(
                1 for e in edges_sorted if e.get("classification") == "FRAMEWORK_CALL"
            ),
        },
    }


def _overlay_sinks(
    nodes: Dict[str, Dict[str, Any]],
    edges: List[Dict[str, Any]],
    dataflow_analysis: Optional[Any],
) -> None:
    """Mark sink nodes from kinds/tags; taint_confirmed only from DataFlow hops."""
    for n in nodes.values():
        kind = n.get("kind") or ""
        if kind in _SINK_KIND_DEFAULT and not n.get("sink_category"):
            n["is_sink"] = True
            n["sink_category"] = _SINK_KIND_DEFAULT[kind]
        if kind == "tool" and "os.system" in str(n.get("label") or ""):
            n["is_sink"] = True
            n["sink_category"] = n.get("sink_category") or "rce"
        n.setdefault("taint_confirmed", False)

    if dataflow_analysis is None:
        return
    by_file_line: Dict[Tuple[str, int], List[Dict[str, Any]]] = {}
    by_file_fn: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    for n in nodes.values():
        f = str(n.get("file") or "").replace("\\", "/")
        line = n.get("line")
        if f and isinstance(line, int) and line > 0:
            by_file_line.setdefault((f, line), []).append(n)
        for site in n.get("callsites") or []:
            sf = str(site.get("file") or "").replace("\\", "/")
            sl = site.get("line")
            if sf and isinstance(sl, int) and sl > 0:
                by_file_line.setdefault((sf, sl), []).append(n)
        label = str(n.get("label") or "")
        fn = label.split("::")[-1] if "::" in label else ""
        if f and fn:
            by_file_fn.setdefault((f, fn), []).append(n)

    for df in getattr(dataflow_analysis, "data_flows", None) or []:
        cat = _SINK_CAT_MAP.get(getattr(df, "sink_category", "") or "", getattr(df, "sink_category", "") or "")
        hops = getattr(df, "hops", None) or []
        confidence = str(getattr(df, "confidence", "") or "high")
        sanitized = bool(getattr(df, "sanitized", False))
        confirmed = bool(hops) and confidence in {"high", "medium"} and not sanitized
        sink_file = str(getattr(df, "file", "") or "").replace("\\", "/")
        sink_line = getattr(df, "line", None)
        sink_fn = str(getattr(df, "sink_function", "") or "")
        candidates: List[Dict[str, Any]] = []
        if sink_file and isinstance(sink_line, int) and sink_line > 0:
            candidates.extend(by_file_line.get((sink_file, sink_line), []))
        if sink_file and sink_fn:
            candidates.extend(by_file_fn.get((sink_file, sink_fn), []))
        seen: Set[str] = set()
        for n in candidates:
            nid = n.get("id") or ""
            if nid in seen:
                continue
            seen.add(nid)
            if cat:
                n["is_sink"] = True
                n["sink_category"] = n.get("sink_category") or cat
                n["sink_type"] = n.get("sink_type") or cat
            # Confirm the sink component, never the API source, and never from
            # architecture reachability alone.
            if confirmed and n.get("kind") in {
                "llm_provider", "database", "tool", "http_client", "mcp_server",
                "vector_db", "retriever", "embedding_model",
            }:
                n["taint_confirmed"] = True
            elif confirmed and n.get("is_sink") and n.get("kind") != "api_endpoint":
                if n.get("sink_category"):
                    n["taint_confirmed"] = True


def _assign_layers(
    nodes: Dict[str, Dict[str, Any]],
    edges: List[Dict[str, Any]],
) -> None:
    """Set layer from kind and observed API adjacency, not name matching."""
    api_ids = {
        nid for nid, n in nodes.items() if n.get("kind") == "api_endpoint"
    }
    from_api: Set[str] = set()
    for e in edges:
        if e.get("source") in api_ids and e.get("classification") in _OBSERVED_CLASSES:
            from_api.add(str(e.get("target") or ""))
    for n in nodes.values():
        kind = str(n.get("kind") or "")
        sink_type = str(n.get("sink_type") or n.get("sink_category") or "")
        if kind == "api_endpoint":
            n["layer"] = LAYER_API
        elif kind in {"llm_provider", "http_client", "mcp_server", "security_control"}:
            n["layer"] = LAYER_EXT
        elif kind in {"database", "vector_db", "retriever", "embedding_model"}:
            n["layer"] = LAYER_DATA
        elif kind == "tool" and sink_type in {"smtp", "rce", "network"}:
            n["layer"] = LAYER_EXT
        elif kind in {"agent", "tool", "memory"}:
            n["layer"] = LAYER_AGENTS
        elif n.get("id") in from_api:
            n["layer"] = LAYER_ORCH
        else:
            n["layer"] = LAYER_BIZ


def _finalize_security_fields(
    nodes: Dict[str, Dict[str, Any]],
    edges: List[Dict[str, Any]],
) -> None:
    """Fill invocation/taint metadata without equating sinks with confirmation."""
    incoming: Dict[str, List[str]] = {}
    for e in edges:
        incoming.setdefault(str(e.get("target") or ""), []).append(
            str(e.get("classification") or "")
        )
    for n in nodes.values():
        n["sink_type"] = n.get("sink_type") or n.get("sink_category") or ""
        n["source_file"] = n.get("source_file") or n.get("file") or ""
        n["source_line"] = n.get("source_line") if n.get("source_line") is not None else n.get("line")
        if n.get("taint_confirmed"):
            n["taint_status"] = "confirmed"
        elif n.get("is_sink") or n.get("sink_type"):
            n["taint_status"] = "unconfirmed"
            n["is_sink"] = True
        else:
            n["taint_status"] = "not_a_sink"
        classes = incoming.get(str(n.get("id") or ""), [])
        if any(c in _OBSERVED_CLASSES for c in classes):
            n["invocation_status"] = "observed"
        elif "STRUCTURAL" in classes:
            n["invocation_status"] = "structural"
        elif "INFERRED" in classes:
            n["invocation_status"] = "inferred"
        elif n.get("kind") == "mcp_server":
            n["invocation_status"] = "structural"
        elif n.get("kind") in {"api_endpoint", "function"}:
            n["invocation_status"] = "observed"
        else:
            n["invocation_status"] = n.get("invocation_status") or "none"
    for e in edges:
        e["invocation_status"] = e.get("evidence_status") or _edge_status(
            str(e.get("classification") or "INFERRED")
        )
        e["source_file"] = e.get("source_file") or e.get("file") or ""
        e["source_line"] = e.get("source_line") if e.get("source_line") is not None else e.get("line")
        e["taint_status"] = "not_a_sink"
        e["sink_type"] = ""


def architecture_graph_to_json(graph: Dict[str, Any]) -> str:
    """Export graph to JSON string."""
    return json.dumps(graph, indent=2, default=str)


def _mermaid_escape(label: str) -> str:
    """Quotes and newlines are unsafe inside Mermaid node labels."""
    return str(label).replace('"', "&quot;").replace("\n", " ")


def _layer_for_node(node: Dict[str, Any]) -> str:
    """Mermaid subgraph title for a node."""
    layer = str(node.get("layer") or "")
    if layer in LAYER_ORDER:
        return layer
    return LAYER_BIZ


def _mermaid_subgraph_id(layer: str) -> str:
    """Mermaid-safe id for a layer title."""
    return _safe_id("L", layer)


def architecture_graph_to_mermaid(graph: Dict[str, Any], layout: str = "TB") -> str:
    """Export a layered Mermaid flowchart. Solid = observed, dashed = not."""
    direction = layout.upper() if layout in ("LR", "TD", "BT", "RL") else "TB"
    lines = [f"flowchart {direction}"]
    node_list = list(graph.get("nodes") or [])
    edge_list = list(graph.get("edges") or [])
    node_map = {n["id"]: n for n in node_list if n.get("id")}

    layers: Dict[str, List[Dict[str, Any]]] = {}
    for n in node_list:
        layers.setdefault(_layer_for_node(n), []).append(n)

    for layer in list(LAYER_ORDER):
        items = layers.get(layer) or []
        if not items:
            continue
        items = sorted(items, key=lambda n: str(n.get("id") or ""))
        sid = _mermaid_subgraph_id(layer)
        lines.append(f'  subgraph {sid}["{_mermaid_escape(layer)}"]')
        for n in items:
            nid = n["id"]
            label = _mermaid_escape(str(n.get("label", nid)))
            if n.get("is_sink"):
                cat = n.get("sink_type") or n.get("sink_category") or "sink"
                mark = " taint" if n.get("taint_status") == "confirmed" or n.get("taint_confirmed") else " unconfirmed"
                label = f"{label} [{cat}{mark}]"
            lines.append(f'    {nid}(["{label}"])')
        lines.append("  end")

    lines.extend([
        "  classDef api fill:#fef3c7,stroke:#d97706,color:#78350f",
        "  classDef orch fill:#ffedd5,stroke:#ea580c,color:#7c2d12",
        "  classDef path fill:#dcfce7,stroke:#16a34a,color:#14532d",
        "  classDef agent fill:#e0e7ff,stroke:#4f46e5,color:#312e81",
        "  classDef data fill:#dbeafe,stroke:#2563eb,color:#1e3a8a",
        "  classDef sink fill:#ffe4e6,stroke:#e11d48,color:#881337",
    ])
    _class_for = {
        LAYER_API: "api",
        LAYER_ORCH: "orch",
        LAYER_BIZ: "path",
        LAYER_AGENTS: "agent",
        LAYER_DATA: "data",
        LAYER_EXT: "sink",
    }
    for n in node_list:
        nid = n.get("id")
        if not nid:
            continue
        cls = _class_for.get(_layer_for_node(n), "path")
        if n.get("is_sink") and cls != "sink":
            if n.get("kind") in {"tool", "database", "llm_provider", "mcp_server", "http_client"}:
                cls = "sink"
        lines.append(f"  class {nid} {cls}")

    seen_edge: Set[Tuple[str, str, str]] = set()
    for e in sorted(
        edge_list,
        key=lambda x: (
            str(x.get("source") or ""),
            str(x.get("target") or ""),
            str(x.get("classification") or ""),
            str(x.get("relationship") or ""),
        ),
    ):
        src, tgt = e.get("source"), e.get("target")
        if src not in node_map or tgt not in node_map:
            continue
        cls = str(e.get("classification") or "")
        rel = str(e.get("label") or e.get("relationship") or "")
        key = (str(src), str(tgt), rel)
        if key in seen_edge:
            continue
        seen_edge.add(key)
        loc = ""
        if e.get("file"):
            loc = str(e.get("file")).replace("\\", "/").split("/")[-1]
            if e.get("line"):
                loc = f"{loc}:{e.get('line')}"
        bits = [rel] if rel else []
        if loc:
            bits.append(loc)
        lbl = " ".join(bits)[:40]
        solid = cls in _OBSERVED_CLASSES
        if solid:
            if lbl:
                lines.append(f"  {src} -->|{lbl}| {tgt}")
            else:
                lines.append(f"  {src} --> {tgt}")
        else:
            if lbl:
                lines.append(f"  {src} -.->|{lbl}| {tgt}")
            else:
                lines.append(f"  {src} -.-> {tgt}")
    return "\n".join(lines)
