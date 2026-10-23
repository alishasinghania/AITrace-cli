"""
Cross-file taint analysis using a lightweight inter-procedural call graph.

Builds a call graph across the repo and uses bidirectional BFS to find
source→sink paths. Confirms or upgrades PatternFindings with reachability evidence.
"""

from __future__ import annotations

import ast
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from ..utils.ast_utils import should_skip_path, walk_python_files, get_call_target_chain
from .pattern_analyzer import PatternFinding
from .taint_catalog import (
    FLOW_META,
    HIGH_IMPACT_SINKS,
    function_has_source_call,
    function_sink_types,
)


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class FunctionNode:
    key: str                       # "relative/file.py::ClassName.method_name"
    file: str
    function_name: str
    qualified_name: str            # ClassName.method_name or just method_name
    line_start: int
    line_end: int
    is_source: bool = False
    source_type: Optional[str] = None   # "fastapi_route" | "websocket" | "celery_task" | etc.
    source_confidence: str = "high"
    is_sink: bool = False
    sink_types: List[str] = field(default_factory=list)
    calls: List[str] = field(default_factory=list)        # normalized call names
    called_by: List[str] = field(default_factory=list)    # FunctionNode keys
    parameters: List[str] = field(default_factory=list)
    is_async: bool = False
    decorators: List[str] = field(default_factory=list)


@dataclass
class TaintPath:
    source_key: str
    sink_key: str
    sink_type: str
    hops: List[str]
    hop_count: int
    confirmed: bool
    partial: bool
    vulnerability_type: str
    confirms_pattern_ids: List[str] = field(default_factory=list)


@dataclass
class CrossFileTaintResult:
    call_graph: Dict[str, FunctionNode]
    taint_paths: List[TaintPath]
    confirmed_pattern_ids: List[str]
    partial_pattern_ids: List[str]
    graph_stats: Dict[str, int]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "taint_paths": [
                {
                    "source_key": tp.source_key,
                    "sink_key": tp.sink_key,
                    "sink_type": tp.sink_type,
                    "hops": tp.hops,
                    "hop_count": tp.hop_count,
                    "confirmed": tp.confirmed,
                    "partial": tp.partial,
                    "vulnerability_type": tp.vulnerability_type,
                    "confirms_pattern_ids": tp.confirms_pattern_ids,
                }
                for tp in self.taint_paths
            ],
            "confirmed_pattern_ids": self.confirmed_pattern_ids,
            "partial_pattern_ids": self.partial_pattern_ids,
            "graph_stats": self.graph_stats,
        }


# ---------------------------------------------------------------------------
# Sink / Source detection helpers
# ---------------------------------------------------------------------------

_LLM_SINK_ATTRS = {
    "create", "generate_content", "generate", "invoke", "ainvoke",
    "run", "arun", "stream", "astream", "predict", "predict_messages",
    "complete", "acomplete", "chat", "kickoff", "kickoff_async",
}
_LLM_SINK_CHAIN_FRAGS = {
    "openai", "anthropic", "cohere", "vertexai", "bedrock",
    "litellm", "ollama", "groq", "together", "replicate",
    "llm", "chain", "agent", "agentexecutor", "messages",
    "completions", "chatmodel", "chatanthropic", "chatopenai",
    "runner", "crew",
}

_SQL_SINK_ATTRS = {"execute", "executemany", "executescript"}
_SQL_SINK_CHAINS = {"cursor", "conn", "session", "db", "database", "engine", "asyncpg"}

_CODE_EXEC_SINK_ATTRS = {"exec", "eval", "compile", "run", "popen", "system", "call", "check_output"}
_CODE_EXEC_SINK_CHAINS = {"subprocess", "os"}

_RETRIEVAL_SINK_ATTRS = {
    "similarity_search", "similarity_search_with_score",
    "max_marginal_relevance_search", "query", "search",
    "get_relevant_documents",
}

_SOURCE_ROUTE_DECORATORS = {
    "get", "post", "put", "delete", "patch", "route",
    "api_route", "websocket",
}
_SOURCE_TASK_DECORATORS = {"task", "shared_task", "celery_task", "agent", "command"}
_SOURCE_CLI_DECORATORS = {"command"}

_PYDANTIC_BASEMODEL_INDICATORS = {"basemodel", "request", "body", "schema"}


def _call_chain_str(node: ast.Call) -> str:
    return ".".join(get_call_target_chain(node)).lower()


def _call_attr(node: ast.Call) -> str:
    if isinstance(node.func, ast.Attribute):
        return node.func.attr.lower()
    if isinstance(node.func, ast.Name):
        return node.func.id.lower()
    return ""


def _sink_types_for_func(func: ast.FunctionDef | ast.AsyncFunctionDef) -> List[str]:
    """Delegate to the shared catalog so taint and PAT-* agree on sinks."""
    return function_sink_types(func)


def _decorator_names(func: ast.FunctionDef | ast.AsyncFunctionDef) -> List[str]:
    names = []
    for d in func.decorator_list:
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


def _detect_source(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    source_text: str,
) -> Tuple[bool, Optional[str], str]:
    """Returns (is_source, source_type, confidence)."""
    dec = _decorator_names(func)

    # HTTP routes
    if any(d in _SOURCE_ROUTE_DECORATORS for d in dec):
        src_type = "websocket_handler" if "websocket" in dec else "fastapi_route"
        # Check for webhook
        func_lower = func.name.lower()
        if "webhook" in func_lower or any("webhook" in str(d) for d in dec):
            src_type = "webhook"
        return True, src_type, "high"

    # Flask route
    if "route" in dec or "app_route" in dec:
        return True, "flask_route", "high"

    # Celery
    if any(d in _SOURCE_TASK_DECORATORS for d in dec):
        return True, "celery_task", "high"

    # CLI
    if any(d in _SOURCE_CLI_DECORATORS for d in dec):
        return True, "cli_command", "high"

    # WebSocket by body content
    func_src = ""
    try:
        lines = source_text.splitlines()
        start = func.lineno - 1
        end = getattr(func, "end_lineno", start + 50)
        func_src = "\n".join(lines[start:end]).lower()
    except Exception:
        pass

    if "websocket.receive_json" in func_src or "receive_text" in func_src or "receive_bytes" in func_src:
        return True, "websocket_handler", "high"

    if "uploadfile" in func_src:
        return True, "file_upload", "high"

    if function_has_source_call(func):
        return True, "user_input", "high"

    # Kafka/Faust
    if any("agent" in d or "topic" in d for d in dec):
        return True, "kafka_consumer", "medium"

    # Heuristic: function named handle_*, process_*, on_*, receive_*
    fn_lower = func.name.lower()
    if any(fn_lower.startswith(p) for p in ("handle_", "process_", "on_", "receive_", "webhook_")):
        params = [a.arg.lower() for a in func.args.args]
        has_request_param = any(
            any(ind in p for ind in ("request", "req", "body", "data", "message")) for p in params
        )
        if has_request_param:
            return True, "inferred_handler", "medium"

    return False, None, "high"


def _extract_calls(func: ast.FunctionDef | ast.AsyncFunctionDef) -> List[str]:
    """Extract normalized call names from function body."""
    calls: Set[str] = set()
    for node in ast.walk(func):
        if isinstance(node, ast.Call):
            chain = get_call_target_chain(node)
            if not chain:
                continue
            full = ".".join(chain).lower()
            # Normalize: strip "self." prefix
            if full.startswith("self."):
                full = full[5:]
            calls.add(full)
            # Also add just the final function name for fuzzy matching
            if len(chain) > 1:
                calls.add(chain[-1].lower())
    return list(calls)


# ---------------------------------------------------------------------------
# Call graph builder
# ---------------------------------------------------------------------------

def _build_call_graph(repo_root: Path) -> Dict[str, FunctionNode]:
    """Walk all Python files and build FunctionNode map."""
    graph: Dict[str, FunctionNode] = {}
    scan_errors: List[str] = []

    for path in walk_python_files(repo_root):
        rel = str(path.relative_to(repo_root))
        # Skip additional non-prod paths
        if any(part in rel for part in ("migrations", "alembic", ".venv", "venv", "dist", "build")):
            continue
        if path.suffix == ".pyi":
            continue

        try:
            source_text = path.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(source_text)
        except (SyntaxError, OSError, ValueError, UnicodeDecodeError):
            continue

        # Detect class context for method keys
        class_contexts: Dict[int, str] = {}  # lineno → class_name
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                for item in ast.walk(node):
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        class_contexts[item.lineno] = node.name

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            func = node
            class_name = class_contexts.get(func.lineno)
            if class_name:
                qualified = f"{class_name}.{func.name}"
            else:
                qualified = func.name

            key = f"{rel}::{qualified}"
            is_src, src_type, src_conf = _detect_source(func, source_text)
            sink_types = _sink_types_for_func(func)
            dec_names = _decorator_names(func)
            params = [a.arg for a in func.args.args + func.args.posonlyargs]

            node_obj = FunctionNode(
                key=key,
                file=rel,
                function_name=func.name,
                qualified_name=qualified,
                line_start=func.lineno,
                line_end=getattr(func, "end_lineno", func.lineno + 50),
                is_source=is_src,
                source_type=src_type,
                source_confidence=src_conf,
                is_sink=bool(sink_types),
                sink_types=sink_types,
                calls=_extract_calls(func),
                called_by=[],
                parameters=params,
                is_async=isinstance(func, ast.AsyncFunctionDef),
                decorators=dec_names,
            )
            # Deduplicate keys (nested functions may share qualified name)
            if key in graph:
                existing = graph[key]
                if not existing.is_source and node_obj.is_source:
                    graph[key] = node_obj
                elif len(node_obj.sink_types) > len(existing.sink_types):
                    graph[key] = node_obj
            else:
                graph[key] = node_obj

    return graph


def _name_index(graph: Dict[str, FunctionNode]) -> Dict[str, List[str]]:
    name_to_keys: Dict[str, List[str]] = {}
    for key, node in graph.items():
        name_to_keys.setdefault(node.function_name.lower(), []).append(key)
        qn = node.qualified_name.lower()
        if qn != node.function_name.lower():
            name_to_keys.setdefault(qn, []).append(key)
    return name_to_keys


def _callee_keys_for_call(
    call_name: str,
    caller_key: str,
    graph: Dict[str, FunctionNode],
    name_to_keys: Dict[str, List[str]],
) -> List[str]:
    """Resolve callees without global short-name matching."""
    if call_name in graph:
        return [call_name]
    caller = graph[caller_key]
    name = call_name.lower()
    out: List[str] = []
    if "." in name:
        parts = name.split(".")
        fn, obj = parts[-1], parts[0]
        for k in name_to_keys.get(fn, []):
            node = graph[k]
            stem = Path(node.file).stem.lower().replace("-", "_")
            if node.function_name.lower() != fn:
                continue
            if obj == stem or obj in node.qualified_name.lower():
                out.append(k)
        return list(dict.fromkeys(out))
    for k in name_to_keys.get(name, []):
        if graph[k].file == caller.file and k != caller_key:
            out.append(k)
    return out


def _build_called_by_index(graph: Dict[str, FunctionNode]) -> None:
    """Populate called_by using precise name/file resolution (not global run() matching)."""
    name_to_keys = _name_index(graph)
    for caller_key, caller in graph.items():
        for call_name in caller.calls:
            for callee_key in _callee_keys_for_call(call_name, caller_key, graph, name_to_keys):
                if callee_key != caller_key and caller_key not in graph[callee_key].called_by:
                    graph[callee_key].called_by.append(caller_key)


# ---------------------------------------------------------------------------
# Bidirectional BFS
# ---------------------------------------------------------------------------

def _forward_bfs(
    graph: Dict[str, FunctionNode],
    max_hops: int,
) -> Dict[str, List[str]]:
    """BFS from all sources. Returns {node_key: path_from_source}."""
    visited: Dict[str, List[str]] = {}
    queue: deque = deque()

    # Seed: all source nodes
    for key, node in graph.items():
        if node.is_source:
            visited[key] = [key]
            queue.append((key, [key]))

    name_to_keys = _name_index(graph)

    while queue:
        current_key, path = queue.popleft()
        if len(path) > max_hops:
            continue
        current = graph.get(current_key)
        if not current:
            continue

        for call_name in current.calls:
            candidates = _callee_keys_for_call(call_name, current_key, graph, name_to_keys)

            for callee_key in candidates:
                if callee_key == current_key:
                    continue
                if callee_key not in visited:
                    new_path = path + [callee_key]
                    visited[callee_key] = new_path
                    queue.append((callee_key, new_path))

    return visited


def _backward_bfs(
    graph: Dict[str, FunctionNode],
    max_hops: int,
) -> Dict[str, List[str]]:
    """BFS from all sinks backwards. Returns {node_key: path_to_sink}."""
    visited: Dict[str, List[str]] = {}
    queue: deque = deque()

    for key, node in graph.items():
        if node.is_sink:
            visited[key] = [key]
            queue.append((key, [key]))

    while queue:
        current_key, path = queue.popleft()
        if len(path) > max_hops:
            continue
        current = graph.get(current_key)
        if not current:
            continue

        for caller_key in current.called_by:
            if caller_key not in visited:
                new_path = [caller_key] + path
                visited[caller_key] = new_path
                queue.append((caller_key, new_path))

    return visited


def _find_taint_paths(
    graph: Dict[str, FunctionNode],
    max_hops: int,
) -> List[TaintPath]:
    """Find confirmed and partial taint paths using bidirectional BFS."""
    forward = _forward_bfs(graph, max_hops)
    backward = _backward_bfs(graph, max_hops)

    paths: List[TaintPath] = []
    seen_paths: Set[Tuple[str, str]] = set()

    # Confirmed: intersection of forward and backward visited
    intersection = set(forward.keys()) & set(backward.keys())
    for meeting_key in intersection:
        meeting_node = graph.get(meeting_key)
        if not meeting_node:
            continue

        forward_path = forward[meeting_key]   # source → meeting
        backward_path = backward[meeting_key]  # meeting → sink

        # Reconstruct full path (avoid duplicate meeting_key)
        full_path = forward_path + backward_path[1:]
        if len(full_path) < 2:
            continue

        source_key = full_path[0]
        sink_key = full_path[-1]

        pair = (source_key, sink_key)
        if pair in seen_paths:
            continue
        seen_paths.add(pair)

        sink_node = graph.get(sink_key)
        sink_type = sink_node.sink_types[0] if sink_node and sink_node.sink_types else "unknown"

        vtype = {
            "llm": "prompt_injection",
            "sql": "sql_injection",
            "rce": "rce",
            "retrieval": "rag_poisoning",
            "http": "ssrf_exfil",
            "email": "excessive_agency",
            "rag_ingest": "rag_poisoning",
        }.get(sink_type, "unknown")

        paths.append(TaintPath(
            source_key=source_key,
            sink_key=sink_key,
            sink_type=sink_type,
            hops=full_path,
            hop_count=len(full_path),
            confirmed=False,
            partial=True,
            vulnerability_type=vtype,
        ))

    # Partial: forward-only paths that reached depth >= 3 without hitting a sink
    for node_key, path in forward.items():
        if len(path) < 3:
            continue
        node = graph.get(node_key)
        if not node or node.is_sink:
            continue
        if (path[0], node_key) not in seen_paths:
            seen_paths.add((path[0], node_key))
            paths.append(TaintPath(
                source_key=path[0],
                sink_key=node_key,
                sink_type="unknown",
                hops=path + ["(sink not reached)"],
                hop_count=len(path),
                confirmed=False,
                partial=True,
                vulnerability_type="unknown",
            ))

    return paths


# ---------------------------------------------------------------------------
# Severity upgrader
# ---------------------------------------------------------------------------

_SEV_UPGRADE: Dict[str, str] = {
    "critical": "critical",
    "high": "critical",
    "medium": "high",
    "low": "medium",
}
_CONF_UPGRADE: Dict[str, str] = {
    "high": "high",
    "medium": "high",
    "low": "medium",
}


def _upgrade_findings(
    pattern_findings: List[PatternFinding],
    paths: List[TaintPath],
    confirmed_ids: List[str],
    partial_ids: List[str],
    data_flows: Optional[List[Any]] = None,
) -> None:
    """Confirm PAT findings only from value-taint DataFlow hits, not call-graph overlap."""
    _SINK_COMPAT: Dict[str, Set[str]] = {
        "PAT-001": {"llm", "retrieval"},
        "PAT-002": {"rce", "llm"},
        "PAT-003": {"sql"},
        "PAT-004": {"rce"},
        "PAT-005": {"llm"},
        "PAT-006": {"llm"},
        "PAT-007": {"llm"},
        "PAT-008": {"llm"},
        "PAT-011": {"llm"},
        "PAT-013": {"llm"},
        "PAT-014": {"retrieval", "llm"},
        "PAT-016": {"llm"},
        "PAT-018": {"llm"},
        "PAT-025": {"rce"},
        "PAT-026": {"retrieval", "llm"},
        "PAT-027": {"llm", "http", "email"},
        "PAT-028": {"llm", "retrieval"},
        "FLOW-RCE": {"rce"},
        "FLOW-SQL": {"sql"},
        "FLOW-LLM": {"llm"},
        "FLOW-HTTP": {"http"},
        "FLOW-EMAIL": {"email"},
        "FLOW-RAG": {"rag_ingest", "retrieval"},
    }

    flows = data_flows or []
    for finding in pattern_findings:
        compatible = _SINK_COMPAT.get(finding.vulnerability_id, {"llm", "sql", "rce", "retrieval"})
        for df in flows:
            if getattr(df, "sanitized", False):
                continue
            cat = getattr(df, "sink_category", "") or ""
            if cat and cat not in compatible:
                continue
            if df.file != finding.file:
                continue
            if finding.line and df.line and abs(int(df.line) - int(finding.line)) > 3:
                continue
            finding.confirmed_by_taint = True
            finding.taint_path = list(getattr(df, "hops", None) or [])
            finding.severity = _SEV_UPGRADE.get(finding.severity, finding.severity)
            finding.confidence = "high"
            if finding.vulnerability_id not in confirmed_ids:
                confirmed_ids.append(finding.vulnerability_id)
            break

        if finding.confirmed_by_taint:
            continue
        partial_by_file: Dict[str, List[TaintPath]] = {}
        for tp in paths:
            if not tp.partial:
                continue
            for hop in tp.hops:
                file_part = hop.split("::")[0] if "::" in hop else hop
                partial_by_file.setdefault(file_part, []).append(tp)
        for tp in partial_by_file.get(finding.file, []):
            old_conf_rank = {"high": 2, "medium": 1, "low": 0}
            if old_conf_rank.get(finding.confidence, 0) < old_conf_rank["medium"]:
                finding.confidence = "medium"
            finding.taint_path = tp.hops
            if finding.vulnerability_id not in partial_ids:
                partial_ids.append(finding.vulnerability_id)
            break


# Pattern IDs that describe the *same* issue as a FLOW-* row at the same sink.
# PAT-001 (RAG shape) is not equivalent to FLOW-LLM (payload in a prompt).
_FLOW_COVERED_BY: Dict[str, Set[str]] = {
    "sql": {"PAT-003", "FLOW-SQL"},
    "rce": {"PAT-002", "PAT-004", "PAT-025", "FLOW-RCE"},
    "llm": {"FLOW-LLM"},
    "http": {"FLOW-HTTP"},
    "email": {"FLOW-EMAIL"},
    "rag_ingest": {"FLOW-RAG", "PAT-026"},
}


def _same_sink_location(finding: PatternFinding, df: Any, slop: int = 0) -> bool:
    """True when a pattern finding and a DataFlow name the same sink site.

    Default slop is 0 so two execute/invoke calls on consecutive lines stay
    distinct. PAT confirmation uses a wider window in ``_upgrade_findings``.
    """
    if finding.file != getattr(df, "file", None):
        return False
    fl = finding.line
    dl = getattr(df, "line", None)
    if not fl or not dl:
        return False
    return abs(int(fl) - int(dl)) <= slop


def _finding_covers_flow(finding: PatternFinding, df: Any, cat: str) -> bool:
    """True when an existing finding already records this flow's issue."""
    if finding.vulnerability_id not in _FLOW_COVERED_BY.get(cat, set()):
        return False
    return _same_sink_location(finding, df)


def _emit_flow_findings(
    pattern_findings: List[PatternFinding],
    paths: List[TaintPath],
    graph: Dict[str, FunctionNode],
    data_flows: Optional[List[Any]] = None,
) -> None:
    """
    Emit FLOW-* findings from value-taint DataFlows, not call-graph reachability.

    Dedup is by (rule, file, line), not by filename. A PAT-* row covers a FLOW
    row only when it is the same sink location and the same issue class.
    """
    seen: Set[Tuple[str, str, str]] = set()
    for df in data_flows or []:
        if getattr(df, "sanitized", False):
            continue
        kind = getattr(df, "taint_kind", "payload") or "payload"
        if kind != "payload":
            continue
        cat = getattr(df, "sink_category", "") or ""
        if cat not in HIGH_IMPACT_SINKS:
            continue
        # FLOW-HTTP is destination control (CWE-918), not every tainted HTTP argument.
        if cat == "http" and getattr(df, "sink_arg_role", "") != "url":
            continue
        meta = FLOW_META.get(cat)
        if not meta:
            continue
        vid, title, severity, category, cwe = meta
        file_name = df.file
        key = (vid, file_name, str(df.line))
        if key in seen:
            continue
        if any(_finding_covers_flow(f, df, cat) for f in pattern_findings):
            continue
        seen.add(key)
        hop_short = " → ".join(getattr(df, "hops", None) or [])
        confidence = getattr(df, "confidence", None) or "high"
        owasp = "LLM01" if cat == "llm" else ("LLM03" if cat == "rag_ingest" else ("LLM02" if cat == "sql" else "LLM08"))
        pattern_findings.append(PatternFinding(
            vulnerability_id=vid,
            title=title,
            severity=severity,
            confidence=confidence,
            category=category,
            owasp_id=owasp,
            cwe=cwe,
            file=file_name,
            line=df.line,
            function_name=getattr(df, "sink_function", None),
            pattern_matched=f"value taint to {cat} sink",
            evidence=[
                f"Confirmed value path: {hop_short}",
                f"Sink type: {cat} at {df.file}:{df.line}",
                f"taint_kind={kind}",
                f"argument role: {getattr(df, 'sink_arg_role', '') or 'n/a'}",
            ],
            framework="taint",
            confirmed_by_taint=confidence != "may",
            taint_path=list(getattr(df, "hops", None) or []),
            remediation=(
                "Block or sanitize untrusted data before this sink. "
                "Prefer allowlists, parameterized APIs, and shell=False with argv lists."
            ),
            cvss_estimate=9.0 if severity == "critical" else 7.5,
            taint_kind=kind,
            source_file=getattr(df, "source_file", "") or "",
            source_line=getattr(df, "source_line", None),
            sink_arg_role=getattr(df, "sink_arg_role", "") or "",
        ))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_crossfile_taint(
    repo_root: Path,
    pattern_findings: List[PatternFinding],
    max_hops: int = 6,
    data_flows: Optional[List[Any]] = None,
) -> CrossFileTaintResult:
    """Build call graph, run BFS for reachability, confirm PAT from value-taint DataFlows."""
    repo_root = Path(repo_root).resolve()

    try:
        graph = _build_call_graph(repo_root)
    except Exception:
        graph = {}

    try:
        _build_called_by_index(graph)
    except Exception:
        pass

    try:
        paths = _find_taint_paths(graph, max_hops)
    except Exception:
        paths = []

    confirmed_ids: List[str] = []
    partial_ids: List[str] = []

    try:
        _upgrade_findings(pattern_findings, paths, confirmed_ids, partial_ids, data_flows=data_flows)
    except Exception:
        pass

    try:
        _emit_flow_findings(pattern_findings, paths, graph, data_flows=data_flows)
    except Exception:
        pass

    sources = sum(1 for n in graph.values() if n.is_source)
    sinks = sum(1 for n in graph.values() if n.is_sink)
    edges = sum(len(n.calls) for n in graph.values())

    return CrossFileTaintResult(
        call_graph=graph,
        taint_paths=paths,
        confirmed_pattern_ids=confirmed_ids,
        partial_pattern_ids=partial_ids,
        graph_stats={
            "nodes": len(graph),
            "edges": edges,
            "sources": sources,
            "sinks": sinks,
            "confirmed_paths": sum(1 for p in paths if p.confirmed),
            "partial_paths": sum(1 for p in paths if p.partial),
        },
    )
