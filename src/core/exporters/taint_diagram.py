"""Mermaid diagrams for value-taint DataFlows (source → hops → sink).

These graphs are built only from interprocedural DataFlow hops. They are not
AIBOM architecture edges and not call-graph BFS reachability.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

_HOP_SRC_SINK = re.compile(
    r"^(?P<file>.+?)::(?P<func>[^:\s]+)(?::(?P<line>\d+))?\s+"
    r"(?P<kind>source|sink)\s+(?P<rest>.*)$"
)
_HOP_ARG = re.compile(
    r"^(?P<sfile>.+?)::(?P<sfunc>\S+)\s+arg\s+->\s+"
    r"(?P<tfile>.+?)::(?P<tfunc>\S+)\s+param\s+(?P<param>\S+)$"
)

_CAT_TITLE = {
    "llm": "LLM sinks",
    "sql": "SQL sinks",
    "rce": "Command execution",
}


def _short_file(path: str) -> str:
    """Return a compact file label for diagram nodes."""
    parts = (path or "").replace("\\", "/").split("/")
    if len(parts) >= 2:
        return "/".join(parts[-2:])
    return parts[-1] if parts else "?"


def mermaid_node_id(file: str, func: str) -> str:
    """Stable Mermaid-safe id for a function in a file."""
    raw = f"n_{file}_{func}"
    safe = []
    for ch in raw:
        if ch.isalnum():
            safe.append(ch)
        else:
            safe.append("_")
    out = "".join(safe)
    while "__" in out:
        out = out.replace("__", "_")
    return out[:80] or "n_unknown"


def parse_taint_hop(hop: str) -> Optional[Dict[str, str]]:
    """Parse one hop string into a typed record, or None if unrecognized."""
    text = (hop or "").strip()
    if not text:
        return None
    m = _HOP_SRC_SINK.match(text)
    if m:
        return {
            "kind": m.group("kind"),
            "file": m.group("file"),
            "func": m.group("func"),
            "line": m.group("line") or "",
            "rest": (m.group("rest") or "").strip(),
        }
    m = _HOP_ARG.match(text)
    if m:
        return {
            "kind": "arg",
            "sfile": m.group("sfile"),
            "sfunc": m.group("sfunc"),
            "tfile": m.group("tfile"),
            "tfunc": m.group("tfunc"),
            "param": m.group("param"),
        }
    return None


def _node_label(file: str, func: str) -> str:
    return f"{_short_file(file)}::{func}"


def taint_flows_to_mermaid(
    flows: Iterable[Any],
    *,
    max_nodes: int = 72,
) -> str:
    """
    Overlay value-taint hops into one left-to-right flowchart.

    Nodes are file::function. Edges follow ordered hops. Multiple flows that
    share a callee (for example run_agent → _ollama_chat) collapse to one node.
    """
    nodes: Dict[str, Dict[str, str]] = {}
    edges: Set[Tuple[str, str, str]] = set()
    cat_nodes: Dict[str, Set[str]] = {"llm": set(), "sql": set(), "rce": set(), "other": set()}

    def add_node(file: str, func: str, role: str, cat: str) -> str:
        nid = mermaid_node_id(file, func)
        prev = nodes.get(nid)
        if prev is None or (prev.get("role") == "mid" and role in {"source", "sink"}):
            nodes[nid] = {
                "id": nid,
                "label": _node_label(file, func).replace('"', "'"),
                "role": role,
            }
        elif role == "sink":
            nodes[nid]["role"] = "sink"
        bucket = cat if cat in cat_nodes else "other"
        cat_nodes[bucket].add(nid)
        return nid

    for df in flows or []:
        cat = str(getattr(df, "sink_category", "") or "other")
        hops = [str(h) for h in (getattr(df, "hops", None) or []) if str(h).strip()]
        parsed = [parse_taint_hop(h) for h in hops]
        parsed = [p for p in parsed if p]
        if not parsed:
            continue
        last_id: Optional[str] = None
        for rec in parsed:
            if rec["kind"] in {"source", "sink"}:
                role = "source" if rec["kind"] == "source" else "sink"
                nid = add_node(rec["file"], rec["func"], role, cat)
                if last_id and last_id != nid:
                    lbl = rec.get("rest", "")[:24]
                    edges.add((last_id, nid, lbl))
                last_id = nid
            elif rec["kind"] == "arg":
                sid = add_node(rec["sfile"], rec["sfunc"], "mid" if last_id else "source", cat)
                tid = add_node(rec["tfile"], rec["tfunc"], "mid", cat)
                edges.add((sid, tid, rec.get("param", "")[:24]))
                last_id = tid

    if not nodes:
        return ""

    if len(nodes) > max_nodes:
        keep: Set[str] = {
            nid for nid, meta in nodes.items() if meta["role"] in {"source", "sink"}
        }
        for src, tgt, _ in edges:
            if src in keep or tgt in keep:
                keep.add(src)
                keep.add(tgt)
            if len(keep) >= max_nodes:
                break
        nodes = {k: v for k, v in nodes.items() if k in keep}
        edges = {e for e in edges if e[0] in nodes and e[1] in nodes}

    lines: List[str] = [
        "%%{init: {'theme': 'dark', 'themeVariables': {"
        "'edgeLabelBackground': '#1e293b', 'lineColor': '#475569', 'fontSize': '12px'"
        "}}}%%",
        "flowchart LR",
        "    classDef sourceCls fill:#7f1d1d,stroke:#ef4444,color:#fecaca,rx:6",
        "    classDef hopCls fill:#1e3a5f,stroke:#3b82f6,color:#93c5fd,rx:6",
        "    classDef sinkCls fill:#7c2d12,stroke:#f97316,color:#fed7aa,rx:6",
    ]

    order = [c for c in ("llm", "sql", "rce", "other") if cat_nodes[c] & set(nodes)]
    for cat in order:
        ids = [i for i in cat_nodes[cat] if i in nodes]
        if not ids:
            continue
        title = _CAT_TITLE.get(cat, cat)
        lines.append(f'    subgraph {cat.upper()}["{title}"]')
        for nid in ids:
            label = nodes[nid]["label"]
            lines.append(f'        {nid}["{label}"]')
        lines.append("    end")

    for src, tgt, lbl in sorted(edges):
        if src not in nodes or tgt not in nodes:
            continue
        if lbl:
            safe = lbl.replace('"', "'").replace("|", "/")
            lines.append(f"    {src} -->|{safe}| {tgt}")
        else:
            lines.append(f"    {src} --> {tgt}")

    sources = [n["id"] for n in nodes.values() if n["role"] == "source"]
    hops = [n["id"] for n in nodes.values() if n["role"] == "mid"]
    sinks = [n["id"] for n in nodes.values() if n["role"] == "sink"]
    if sources:
        lines.append(f"    class {','.join(sources)} sourceCls")
    if hops:
        lines.append(f"    class {','.join(hops)} hopCls")
    if sinks:
        lines.append(f"    class {','.join(sinks)} sinkCls")
    return "\n".join(lines)


def taint_mermaid_for_analysis(dataflow_analysis: Any) -> str:
    """Return a taint Mermaid flowchart, or empty string when there are no hops."""
    flows = list(getattr(dataflow_analysis, "data_flows", None) or []) if dataflow_analysis else []
    return taint_flows_to_mermaid(flows)
