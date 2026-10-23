"""Taint-flow graph built only from DataFlow evidence.

Architecture edges and call-graph BFS are not treated as confirmed value-taint.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple

from .finding_contract import honest_line, serialize_finding
from .taint_diagram import parse_taint_hop

_MAX_FLOWS = 48
_MAX_STRUCTURAL = 8


def _flow_id(index: int, df: Any) -> str:
    sink = str(getattr(df, "file", "") or "")
    line = getattr(df, "line", None)
    cat = str(getattr(df, "sink_category", "") or "")
    return f"flow-{index}-{cat}-{sink}-{line}"


def _node_id(role: str, file: str, func: str, line: Any) -> str:
    ln = honest_line(line)
    return f"{role}:{file}::{func}:{ln or 'na'}"


def _match_findings(df: Any, findings: Optional[List[Any]]) -> List[str]:
    """Return real finding ids whose sink location matches this DataFlow."""
    if not findings:
        return []
    sink_file = getattr(df, "file", None)
    sink_line = honest_line(getattr(df, "line", None))
    ids: List[str] = []
    for f in findings:
        fid = str(getattr(f, "id", "") or "")
        ser = serialize_finding(f)
        if ser.get("sink_file") == sink_file and honest_line(ser.get("sink_line")) == sink_line:
            ids.append(fid)
    return ids


def build_taint_flow_graph(
    dataflow_analysis: Optional[Any] = None,
    findings: Optional[List[Any]] = None,
    crossfile_taint: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    Graph of confirmed value-taint DataFlows.

    ``flow_count`` is the number of DataFlow rows included (unique source+sink
    identities as emitted by the analyzer). ``unique_sink_count`` counts
    distinct (file, line, sink_category) sinks. Structural BFS paths are
    listed separately and are not confirmed taint.
    """
    flows_in = list(getattr(dataflow_analysis, "data_flows", None) or []) if dataflow_analysis else []
    nodes: Dict[str, Dict[str, Any]] = {}
    edges: List[Dict[str, Any]] = []
    flow_records: List[Dict[str, Any]] = []
    sinks: Set[Tuple[str, Optional[int], str]] = set()

    def add_node(nid: str, **kwargs: Any) -> None:
        if nid not in nodes:
            nodes[nid] = {"id": nid, **kwargs}

    for i, df in enumerate(flows_in[:_MAX_FLOWS]):
        hops = [str(h) for h in (getattr(df, "hops", None) or []) if str(h).strip()]
        parsed = [p for p in (parse_taint_hop(h) for h in hops) if p]
        src_file = getattr(df, "source_file", None) or getattr(df, "file", None)
        src_line = honest_line(getattr(df, "source_line", None))
        sink_file = getattr(df, "file", None)
        sink_line = honest_line(getattr(df, "line", None))
        cat = str(getattr(df, "sink_category", "") or "")
        kind = str(getattr(df, "taint_kind", "") or "")
        role = str(getattr(df, "sink_arg_role", "") or "")
        conf = str(getattr(df, "confidence", "") or "")
        fid = _flow_id(i, df)
        finding_ids = _match_findings(df, findings)
        hops_detail: List[Dict[str, Any]] = []
        path_ids: List[str] = []

        if parsed:
            last: Optional[str] = None
            for rec in parsed:
                if rec["kind"] in {"source", "sink"}:
                    nid = _node_id(rec["kind"], rec["file"], rec["func"], rec.get("line"))
                    add_node(
                        nid,
                        role=rec["kind"],
                        file=rec["file"],
                        function=rec["func"],
                        line=honest_line(rec.get("line")),
                        label=f"{rec['file'].split('/')[-1]}::{rec['func']}",
                    )
                    hops_detail.append({
                        "kind": rec["kind"],
                        "file": rec["file"],
                        "function": rec["func"],
                        "line": honest_line(rec.get("line")),
                        "detail": rec.get("rest") or "",
                    })
                    if last and last != nid:
                        edges.append({
                            "source": last,
                            "target": nid,
                            "flow_id": fid,
                            "evidence_status": "confirmed_value_taint",
                            "taint_kind": kind,
                        })
                    last = nid
                    path_ids.append(nid)
                elif rec["kind"] == "arg":
                    sid = _node_id("mid", rec["sfile"], rec["sfunc"], None)
                    tid = _node_id("mid", rec["tfile"], rec["tfunc"], None)
                    add_node(
                        sid,
                        role="intermediate",
                        file=rec["sfile"],
                        function=rec["sfunc"],
                        line=None,
                        label=f"{rec['sfile'].split('/')[-1]}::{rec['sfunc']}",
                    )
                    add_node(
                        tid,
                        role="intermediate",
                        file=rec["tfile"],
                        function=rec["tfunc"],
                        line=None,
                        label=f"{rec['tfile'].split('/')[-1]}::{rec['tfunc']}",
                    )
                    hops_detail.append({
                        "kind": "call",
                        "file": rec["sfile"],
                        "function": rec["sfunc"],
                        "line": None,
                        "detail": f"arg -> {rec['tfunc']} param {rec.get('param', '')}",
                    })
                    edges.append({
                        "source": sid,
                        "target": tid,
                        "flow_id": fid,
                        "evidence_status": "confirmed_value_taint",
                        "taint_kind": kind,
                        "label": rec.get("param") or "arg",
                    })
                    last = tid
                    path_ids.extend([sid, tid])
        else:
            sid = _node_id("source", src_file or "?", "source", src_line)
            tid = _node_id("sink", sink_file or "?", str(getattr(df, "sink", "sink")), sink_line)
            add_node(
                sid,
                role="source",
                file=src_file,
                function="",
                line=src_line,
                label=str(getattr(df, "source", "source")),
            )
            add_node(
                tid,
                role="sink",
                file=sink_file,
                function=str(getattr(df, "sink_function", "") or ""),
                line=sink_line,
                label=str(getattr(df, "sink", "sink")),
            )
            edges.append({
                "source": sid,
                "target": tid,
                "flow_id": fid,
                "evidence_status": "limited_source_sink",
                "taint_kind": kind,
            })
            path_ids = [sid, tid]

        evidence_class = "confirmed_value_taint" if parsed else "limited_source_sink"
        if kind and kind != "payload":
            evidence_class = f"value_taint:{kind}"
        flow_records.append({
            "id": fid,
            "taint_kind": kind,
            "sink_category": cat,
            "sink_arg_role": role,
            "confidence": conf,
            "sanitized": bool(getattr(df, "sanitized", False)),
            "source_file": src_file,
            "source_line": src_line,
            "sink_file": sink_file,
            "sink_line": sink_line,
            "sink": getattr(df, "sink", ""),
            "finding_ids": finding_ids,
            "evidence_class": evidence_class,
            "hops": hops_detail,
            "path_node_ids": path_ids,
            "ssrf_candidate": cat == "http" and role == "url" and kind == "payload",
        })
        sinks.add((str(sink_file or ""), sink_line, cat))

    structural: List[Dict[str, Any]] = []
    if crossfile_taint is not None:
        for p in list(getattr(crossfile_taint, "taint_paths", None) or [])[:_MAX_STRUCTURAL]:
            structural.append({
                "evidence_class": "structural_reachability",
                "not_value_taint": True,
                "confirmed": bool(getattr(p, "confirmed", False)),
                "source": getattr(p, "source_key", ""),
                "sink": getattr(p, "sink_key", ""),
                "hop_count": getattr(p, "hop_count", None),
            })

    return {
        "kind": "value_taint",
        "not_architecture": True,
        "flow_count": len(flow_records),
        "unique_sink_count": len(sinks),
        "truncated": len(flows_in) > _MAX_FLOWS,
        "nodes": list(nodes.values()),
        "edges": edges,
        "flows": flow_records,
        "structural_reachability": structural,
        "notes": [
            "Confirmed taint edges come only from DataFlow hops or source/sink pairs.",
            "structural_reachability is call-graph BFS and is not value-taint.",
            "FLOW-HTTP / SSRF applies only when sink_arg_role is url and taint_kind is payload.",
        ],
    }
