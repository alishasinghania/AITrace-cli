"""Presentation-layer architecture overview.

Builds compact workflow diagrams and a searchable inventory from an existing
architecture graph and AIBOM. Does not invent edges, does not merge distinct
node identities, and does not change analyzer output.
"""

from __future__ import annotations

import html as _html
from collections import defaultdict
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

VISIBLE_CAP = 8
ARCH_VISIBLE_CAP = 80
_CARD_W = 168
_CARD_H = 56
_GAP_X = 16
_GAP_Y = 14
_PAD = 18
_LAYER_MAX_COLS = 5
_LAYER_TITLE_H = 22
_LAYER_INSET = 14
_LAYER_GAP = 22
_COL_GAP = 22
_TAINT_CARD_W = 228
_TAINT_CARD_H = 78
_TAINT_GAP = 88

LAYER_ORDER: Tuple[str, ...] = (
    "api_endpoint",
    "agent",
    "function",
    "prompt_builder",
    "memory",
    "llm_provider",
    "embedding_model",
    "retriever",
    "vector_db",
    "tool",
    "http_client",
    "database",
    "mcp_server",
    "security_control",
)

# GitDiagram-style bands for the overview canvas (not one column per kind).
GITDIAGRAM_LAYER_ORDER: Tuple[str, ...] = (
    "API",
    "Orchestration",
    "Business Logic / Agent Workflows",
    "Agents / Tools / Integrations",
    "Data Stores / Retrieval",
    "External Services / Security Sinks",
)

_KIND_LAYER_FALLBACK: Dict[str, str] = {
    "api_endpoint": "API",
    "function": "Business Logic / Agent Workflows",
    "prompt_builder": "Orchestration",
    "memory": "Agents / Tools / Integrations",
    "agent": "Agents / Tools / Integrations",
    "tool": "Agents / Tools / Integrations",
    "vector_db": "Data Stores / Retrieval",
    "retriever": "Data Stores / Retrieval",
    "embedding_model": "Data Stores / Retrieval",
    "database": "Data Stores / Retrieval",
    "llm_provider": "External Services / Security Sinks",
    "http_client": "External Services / Security Sinks",
    "mcp_server": "External Services / Security Sinks",
    "security_control": "External Services / Security Sinks",
}

_LAYER_FILL: Dict[str, str] = {
    "API": "#fffbeb",
    "Orchestration": "#fff7ed",
    "Business Logic / Agent Workflows": "#eff6ff",
    "Agents / Tools / Integrations": "#eef2ff",
    "Data Stores / Retrieval": "#eff6ff",
    "External Services / Security Sinks": "#fff1f2",
    "Other": "#f8fafc",
}

# Presentation titles only — does not change graph membership.
_LAYER_DISPLAY_TITLE: Dict[str, str] = {
    "API": "1. HTTP API",
    "Orchestration": "2. Routing / orchestration",
    "Business Logic / Agent Workflows": "3. Request paths",
    "Agents / Tools / Integrations": "4. Agents / tools",
    "Data Stores / Retrieval": "5. Knowledge / RAG",
    "External Services / Security Sinks": "6. Trust-boundary sinks",
    "Other": "Other",
}

# fill, stroke, text — mermaid-style node colors
_LAYER_NODE_STYLE: Dict[str, Tuple[str, str, str]] = {
    "API": ("#fef3c7", "#d97706", "#78350f"),
    "Orchestration": ("#ffedd5", "#ea580c", "#7c2d12"),
    "Business Logic / Agent Workflows": ("#dcfce7", "#16a34a", "#14532d"),
    "Agents / Tools / Integrations": ("#e0e7ff", "#4f46e5", "#312e81"),
    "Data Stores / Retrieval": ("#dbeafe", "#2563eb", "#1e3a8a"),
    "External Services / Security Sinks": ("#ffe4e6", "#e11d48", "#881337"),
    "Other": ("#f8fafc", "#64748b", "#0f172a"),
}

_AI_SINKS = frozenset({
    "llm_provider",
    "tool",
    "database",
    "http_client",
    "retriever",
    "vector_db",
    "mcp_server",
    "embedding_model",
    "memory",
})

# Isolated nodes of these kinds still belong on the architecture canvas.
_CANVAS_KINDS = frozenset({
    "api_endpoint",
    "agent",
    "prompt_builder",
    "llm_provider",
    "embedding_model",
    "retriever",
    "vector_db",
    "memory",
    "tool",
    "mcp_server",
    "database",
    "http_client",
    "security_control",
})

_KIND_COLOR: Dict[str, str] = {
    "api_endpoint": "#d97706",
    "agent": "#7c3aed",
    "prompt_builder": "#0891b2",
    "llm_provider": "#2563eb",
    "embedding_model": "#16a34a",
    "vector_db": "#059669",
    "retriever": "#0d9488",
    "memory": "#9333ea",
    "tool": "#e11d48",
    "mcp_server": "#ea580c",
    "database": "#0284c7",
    "http_client": "#64748b",
    "security_control": "#15803d",
    "function": "#475569",
    "source": "#dc2626",
    "sink": "#c2410c",
    "intermediate": "#2563eb",
}

_KIND_TITLE: Dict[str, str] = {
    "api_endpoint": "API",
    "agent": "Agent",
    "function": "Function",
    "prompt_builder": "Prompt",
    "memory": "Memory",
    "llm_provider": "LLM",
    "embedding_model": "Embedding",
    "retriever": "Retriever",
    "vector_db": "Vector DB",
    "tool": "Tool",
    "http_client": "HTTP",
    "database": "Database",
    "mcp_server": "MCP",
    "security_control": "Control",
    "source": "Source",
    "sink": "Sink",
    "intermediate": "Hop",
}


def _e(value: object) -> str:
    """Escape text for SVG/HTML."""
    return _html.escape(str(value if value is not None else ""), quote=True)


def _safe_dom(value: object) -> str:
    """DOM-safe token for svg/marker ids."""
    chars = []
    for ch in str(value or "n"):
        chars.append(ch if ch.isalnum() else "-")
    out = "".join(chars).strip("-") or "n"
    while "--" in out:
        out = out.replace("--", "-")
    return out[:80]


def _clip(text: object, limit: int) -> str:
    """Clip a label so card text stays inside the rounded rect."""
    s = " ".join(str(text or "").split())
    if len(s) <= limit:
        return s
    return s[: max(limit - 1, 1)] + "…"


def _loc(node: Dict[str, Any]) -> str:
    """File:line when recorded; empty string otherwise."""
    file = str(node.get("file") or "")
    line = node.get("line")
    if file and line:
        return f"{file}:{line}"
    return file


def _kind(node: Dict[str, Any]) -> str:
    return str(node.get("kind") or node.get("role") or "function")


def connected_components(graph: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Undirected connected components of observed architecture edges.

    Isolated nodes are returned as single-node components. Original node and
    edge dicts are reused (same identities).
    """
    graph = graph or {}
    nodes = list(graph.get("nodes") or [])
    edges = list(graph.get("edges") or [])
    by_id = {str(n.get("id")): n for n in nodes if n.get("id")}
    adj: Dict[str, Set[str]] = defaultdict(set)
    for e in edges:
        src, tgt = str(e.get("source") or ""), str(e.get("target") or "")
        if src in by_id and tgt in by_id and src != tgt:
            adj[src].add(tgt)
            adj[tgt].add(src)
    seen: Set[str] = set()
    out: List[Dict[str, Any]] = []
    for nid in by_id:
        if nid in seen:
            continue
        stack = [nid]
        group: Set[str] = set()
        while stack:
            cur = stack.pop()
            if cur in group:
                continue
            group.add(cur)
            seen.add(cur)
            stack.extend(adj.get(cur, ()))
        c_nodes = [by_id[i] for i in group]
        c_edges = [
            e for e in edges
            if str(e.get("source")) in group and str(e.get("target")) in group
        ]
        out.append({"nodes": c_nodes, "edges": c_edges})
    out.sort(key=lambda c: (-len(c["edges"]), -len(c["nodes"])))
    return out


def _directed_adj(edges: Iterable[Dict[str, Any]]) -> Dict[str, List[str]]:
    adj: Dict[str, List[str]] = defaultdict(list)
    for e in edges:
        src, tgt = str(e.get("source") or ""), str(e.get("target") or "")
        if src and tgt and src != tgt and tgt not in adj[src]:
            adj[src].append(tgt)
    return adj


def pick_visible_ids(
    nodes: List[Dict[str, Any]],
    edges: List[Dict[str, Any]],
    cap: int = VISIBLE_CAP,
) -> List[str]:
    """
    Choose up to ``cap`` node ids for the compact diagram.

    Prefers API/agent roots and paths that reach LLM/tool/database sinks.
    Remaining identities are returned by the caller as hidden, not dropped.
    """
    if cap <= 0:
        return []
    by_id = {str(n.get("id")): n for n in nodes if n.get("id")}
    ids = list(by_id)
    if len(ids) <= cap:
        return ids
    adj = _directed_adj(edges)

    def reaches_sink(start: str) -> bool:
        stack = [start]
        seen_r = {start}
        while stack:
            cur = stack.pop()
            if cur != start and _kind(by_id.get(cur, {})) in _AI_SINKS:
                return True
            for nxt in adj.get(cur, []):
                if nxt not in seen_r:
                    seen_r.add(nxt)
                    stack.append(nxt)
        return False

    apis = [i for i in ids if _kind(by_id[i]) == "api_endpoint"]
    agents = [i for i in ids if _kind(by_id[i]) == "agent"]
    sink_apis = [i for i in apis if reaches_sink(i)]
    other_apis = [i for i in apis if i not in set(sink_apis)]
    roots = sink_apis or apis or agents or ids[:1]

    visible: List[str] = []
    seen: Set[str] = set()

    def add(nid: str) -> None:
        if nid in by_id and nid not in seen and len(visible) < cap:
            seen.add(nid)
            visible.append(nid)

    def walk(start: str) -> None:
        queue = [start]
        qseen = {start}
        while queue and len(visible) < cap:
            cur = queue.pop(0)
            kids = list(adj.get(cur, []))
            kids.sort(key=lambda t: 0 if _kind(by_id.get(t, {})) in _AI_SINKS else 1)
            for kid in kids:
                add(kid)
                if kid not in qseen:
                    qseen.add(kid)
                    queue.append(kid)

    # GitDiagram always shows the HTTP/WebSocket surface, then sinks, then paths.
    for nid in apis:
        add(nid)
    for nid in agents:
        add(nid)
    for nid in ids:
        if _kind(by_id[nid]) in _AI_SINKS:
            add(nid)
    for nid in roots:
        walk(nid)
    for nid in other_apis:
        walk(nid)
    for nid in ids:
        add(nid)
    return visible


def _workflow_title(nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]]) -> str:
    """Short title from the first API, agent, or LLM in the component."""
    for kind, prefix in (
        ("api_endpoint", "API"),
        ("agent", "Agent"),
        ("llm_provider", "LLM"),
        ("tool", "Tool"),
        ("database", "Database"),
        ("retriever", "Retrieval"),
        ("mcp_server", "MCP"),
    ):
        hits = [n for n in nodes if _kind(n) == kind]
        if hits:
            label = _clip(hits[0].get("label") or hits[0].get("id"), 28)
            extra = f" +{len(hits) - 1}" if len(hits) > 1 else ""
            return f"{prefix} {label}{extra}"
    if not edges:
        return "Disconnected component"
    return f"Observed path ({len(nodes)})"


def _api_subgraphs(comp: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Split a large connected component into API-rooted directed subgraphs.

    Nodes not reachable from any API stay in a leftover component. No edges
    are added.
    """
    nodes = list(comp.get("nodes") or [])
    edges = list(comp.get("edges") or [])
    by_id = {str(n.get("id")): n for n in nodes if n.get("id")}
    adj = _directed_adj(edges)
    apis = [n for n in nodes if _kind(n) == "api_endpoint"]
    if len(apis) <= 1 or len(nodes) <= VISIBLE_CAP:
        return [comp]
    used: Set[str] = set()
    out: List[Dict[str, Any]] = []
    for api in apis:
        start = str(api.get("id"))
        reach = {start}
        stack = [start]
        while stack:
            cur = stack.pop()
            for nxt in adj.get(cur, []):
                if nxt not in reach:
                    reach.add(nxt)
                    stack.append(nxt)
        used |= reach
        sub_nodes = [by_id[i] for i in reach if i in by_id]
        sub_edges = [
            e for e in edges
            if str(e.get("source")) in reach and str(e.get("target")) in reach
        ]
        if sub_nodes:
            out.append({"nodes": sub_nodes, "edges": sub_edges})
    leftover_ids = [i for i in by_id if i not in used]
    if leftover_ids:
        sub_nodes = [by_id[i] for i in leftover_ids]
        sub_edges = [
            e for e in edges
            if str(e.get("source")) in leftover_ids and str(e.get("target")) in leftover_ids
        ]
        out.append({"nodes": sub_nodes, "edges": sub_edges})
    return out or [comp]


def _layer_name(node: Dict[str, Any]) -> str:
    """GitDiagram band from assigned layer, else kind fallback."""
    layer = str(node.get("layer") or "")
    if layer in GITDIAGRAM_LAYER_ORDER:
        return layer
    return _KIND_LAYER_FALLBACK.get(_kind(node), "Other")


def _layer_groups(nodes: List[Dict[str, Any]]) -> List[Tuple[str, List[Dict[str, Any]]]]:
    """Group visible nodes into GitDiagram-style bands; omit empty layers."""
    buckets: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for n in nodes:
        buckets[_layer_name(n)].append(n)

    def _sort_key(n: Dict[str, Any]) -> Tuple[str, str, int, str]:
        return (
            str(n.get("module") or n.get("file") or ""),
            str(n.get("route_path") or n.get("label") or ""),
            int(n.get("line") or 0),
            str(n.get("id") or ""),
        )

    groups: List[Tuple[str, List[Dict[str, Any]]]] = []
    for name in list(GITDIAGRAM_LAYER_ORDER) + ["Other"]:
        items = buckets.get(name) or []
        if items:
            groups.append((name, sorted(items, key=_sort_key)))
    return groups


def _wrap_label(text: object, width: int = 28, max_lines: int = 2) -> List[str]:
    """Word-wrap a label; last line ellipsizes only if still too long."""
    words = str(text or "").split()
    if not words:
        return [""]
    lines: List[str] = []
    cur = ""
    for w in words:
        trial = f"{cur} {w}".strip()
        if len(trial) <= width:
            cur = trial
            continue
        if cur:
            lines.append(cur)
        cur = w
        if len(lines) == max_lines - 1:
            break
    if len(lines) < max_lines and cur:
        lines.append(cur)
    if len(lines) == max_lines and lines[-1] and len(lines[-1]) > width:
        lines[-1] = _clip(lines[-1], width)
    leftover = words[len(" ".join(lines).split()):]
    if leftover and len(lines) == max_lines:
        lines[-1] = _clip(lines[-1] + " " + leftover[0], width)
    return lines[:max_lines] or [""]


def _barycentric_sort(
    items: List[Dict[str, Any]],
    edges: List[Dict[str, Any]],
    pos: Dict[str, Tuple[float, float]],
) -> List[Dict[str, Any]]:
    """Order nodes by average X of already-placed neighbors to reduce crossings."""
    ids = {str(n.get("id")) for n in items}

    def score(n: Dict[str, Any]) -> Tuple[float, str]:
        nid = str(n.get("id") or "")
        xs: List[float] = []
        for e in edges:
            src, tgt = str(e.get("source") or ""), str(e.get("target") or "")
            other = tgt if src == nid else src if tgt == nid else ""
            if other and other not in ids and other in pos:
                xs.append(pos[other][0])
        avg = sum(xs) / len(xs) if xs else 0.0
        return (avg, nid)

    return sorted(items, key=score)


def _display_parts(node: Dict[str, Any]) -> Tuple[str, str]:
    """Title + subtitle for a flowchart node (name, then file)."""
    raw = str(node.get("label") or node.get("id") or "")
    file = _basename(node.get("file") or "") or str(node.get("module") or "")
    if _kind(node) == "api_endpoint":
        return raw, file
    if "::" in raw:
        _, name = raw.split("::", 1)
        return name, file
    return raw, file


def _node_style(node: Dict[str, Any]) -> Tuple[str, str, str]:
    """Fill/stroke/text for a mermaid-like node. Sinks use the trust-boundary palette."""
    layer = _layer_name(node)
    if node.get("is_sink") and layer != "External Services / Security Sinks":
        if _kind(node) in {"tool", "database", "llm_provider", "mcp_server", "http_client"}:
            return _LAYER_NODE_STYLE["External Services / Security Sinks"]
    return _LAYER_NODE_STYLE.get(layer, _LAYER_NODE_STYLE["Other"])


def _pack_cluster(
    layer: str,
    items: List[Dict[str, Any]],
    x: float,
    y: float,
    cols: int,
    pos: Dict[str, Tuple[float, float]],
) -> Tuple[float, float, float, float]:
    """Place nodes in a subgraph box. Returns (x, y, w, h)."""
    cols = max(cols, 1)
    rows = (len(items) + cols - 1) // cols if items else 1
    body_w = cols * _CARD_W + max(cols - 1, 0) * _GAP_X
    body_h = rows * _CARD_H + max(rows - 1, 0) * _GAP_Y
    w = body_w + _LAYER_INSET * 2
    h = _LAYER_TITLE_H + _LAYER_INSET + body_h + _LAYER_INSET
    origin_x = x + _LAYER_INSET
    origin_y = y + _LAYER_TITLE_H + _LAYER_INSET
    for i, node in enumerate(items):
        ci = i % cols
        ri = i // cols
        pos[str(node.get("id"))] = (
            origin_x + ci * (_CARD_W + _GAP_X),
            origin_y + ri * (_CARD_H + _GAP_Y),
        )
    return x, y, w, h


def workflow_svg(
    visible: List[Dict[str, Any]],
    edges: List[Dict[str, Any]],
    *,
    svg_id: str = "",
) -> str:
    """System-map SVG: API on top, request paths / agents in the middle, sinks below."""
    if not visible:
        return ""
    grouped = {name: items for name, items in _layer_groups(visible)}
    pos: Dict[str, Tuple[float, float]] = {}
    frames: List[Tuple[str, float, float, float, float]] = []

    def place(layer: str, x: float, y: float, cols: int) -> Tuple[float, float]:
        items = grouped.get(layer) or []
        if not items:
            return 0.0, 0.0
        ordered = _barycentric_sort(items, edges, pos) if pos else items
        fx, fy, fw, fh = _pack_cluster(layer, ordered, x, y, cols, pos)
        frames.append((layer, fx, fy, fw, fh))
        return fw, fh

    y = float(_PAD)
    _api_w, api_h = place("API", float(_PAD), y, 5)
    if api_h:
        y += api_h + _LAYER_GAP
    mid_y = y
    left_x = float(_PAD)
    biz_w, biz_h = place("Business Logic / Agent Workflows", left_x, mid_y, 4)
    right_x = left_x + biz_w + _COL_GAP if biz_w else left_x
    orch_w, orch_h = place("Orchestration", right_x, mid_y, 3)
    if orch_w:
        right_x = right_x if biz_w else left_x
    data_y = mid_y + (biz_h or 0) + (_LAYER_GAP if biz_h else 0)
    _data_w, data_h = place("Data Stores / Retrieval", left_x, data_y, 3)
    agents_y = mid_y + (orch_h or 0) + (_LAYER_GAP if orch_h else 0)
    if not orch_w:
        agents_y = data_y if data_h else mid_y
        right_x = left_x + max(biz_w, _data_w) + _COL_GAP if (biz_w or _data_w) else left_x
    _ag_w, ag_h = place("Agents / Tools / Integrations", right_x, agents_y, 3)
    mid_bottom = max(
        data_y + data_h if data_h else mid_y,
        agents_y + ag_h if ag_h else mid_y,
        mid_y + orch_h,
        mid_y + biz_h,
    )
    other_w, other_h = place("Other", float(_PAD), mid_bottom + _LAYER_GAP, 4)
    sink_y = mid_bottom + (_LAYER_GAP if mid_bottom > mid_y else 0)
    if other_h:
        sink_y = mid_bottom + _LAYER_GAP + other_h + _LAYER_GAP
    sink_w, sink_h = place("External Services / Security Sinks", float(_PAD), sink_y, 5)
    width = _PAD * 2
    height = _PAD
    for _layer, fx, fy, fw, fh in frames:
        width = max(width, fx + fw + _PAD)
        height = max(height, fy + fh + _PAD)
    legend_h = 40
    width = int(min(max(width, 720), 1800))
    height = int(max(height, 220) + legend_h)

    marker_id = f"arr-{_safe_dom(svg_id or 'wf')}"
    marker_dash = f"arrd-{_safe_dom(svg_id or 'wf')}"
    parts = [
        f"<svg class='wf-svg' id='{_e(_safe_dom(svg_id or 'wf'))}' role='img' "
        f"viewBox='0 0 {width} {height}' width='{width}' height='{height}' "
        f"xmlns='http://www.w3.org/2000/svg'>",
        f"<defs>"
        f"<marker id='{_e(marker_id)}' markerWidth='8' markerHeight='8' "
        f"refX='7' refY='4' orient='auto'>"
        "<polygon points='0 0, 8 4, 0 8' fill='#6366f1'/></marker>"
        f"<marker id='{_e(marker_dash)}' markerWidth='8' markerHeight='8' "
        f"refX='7' refY='4' orient='auto'>"
        "<polygon points='0 0, 8 4, 0 8' fill='#94a3b8'/></marker>"
        f"</defs>",
    ]
    for layer, fx, fy, fw, fh in frames:
        fill = _LAYER_FILL.get(layer, "#f8fafc")
        title = _LAYER_DISPLAY_TITLE.get(layer, layer)
        parts.append(
            f"<g class='wf-layer' data-layer='{_e(layer)}'>"
            f"<rect x='{fx}' y='{fy}' width='{fw}' height='{fh}' rx='12' "
            f"fill='{fill}' stroke='#cbd5e1'/>"
            f"<text x='{fx + 14}' y='{fy + 16}' fill='#475569' font-size='12' "
            f"font-family='ui-sans-serif,system-ui,sans-serif' font-weight='700'>"
            f"{_e(title)}</text></g>"
        )
    vis_ids = {str(n.get("id")) for n in visible}
    routed = 0
    for e in edges:
        src, tgt = str(e.get("source") or ""), str(e.get("target") or "")
        if src not in pos or tgt not in pos or src not in vis_ids or tgt not in vis_ids:
            continue
        x1, y1 = pos[src]
        x2, y2 = pos[tgt]
        same_row = abs(y1 - y2) < 4
        spread = 10 * ((routed % 5) - 2)
        routed += 1
        if same_row:
            if x1 <= x2:
                sx, sy, tx, ty = x1 + _CARD_W, y1 + _CARD_H / 2, x2, y2 + _CARD_H / 2
            else:
                sx, sy, tx, ty = x1, y1 + _CARD_H / 2, x2 + _CARD_W, y2 + _CARD_H / 2
            mid = (sx + tx) / 2
            d = (
                f"M{sx:.1f},{sy:.1f} C{mid:.1f},{sy + spread:.1f} "
                f"{mid:.1f},{ty + spread:.1f} {tx:.1f},{ty:.1f}"
            )
        else:
            going_down = y2 >= y1
            sx = x1 + _CARD_W / 2 + spread
            tx = x2 + _CARD_W / 2
            if going_down:
                sy, ty = y1 + _CARD_H, y2
            else:
                sy, ty = y1, y2 + _CARD_H
            mid = (sy + ty) / 2
            d = f"M{sx:.1f},{sy:.1f} C{sx:.1f},{mid:.1f} {tx:.1f},{mid:.1f} {tx:.1f},{ty:.1f}"
        cls = str(e.get("classification") or "")
        status = str(e.get("invocation_status") or e.get("evidence_status") or "")
        dashed = cls in {"STRUCTURAL", "INFERRED"} or status in {"structural", "inferred"}
        dash = " stroke-dasharray='6 4'" if dashed else ""
        color = "#94a3b8" if dashed else "#6366f1"
        mk = marker_dash if dashed else marker_id
        parts.append(
            f"<path d='{d}' fill='none' stroke='{color}' stroke-width='1.8'{dash} "
            f"marker-end='url(#{_e(mk)})'/>"
        )
    for node in visible:
        nid = str(node.get("id") or "")
        if nid not in pos:
            continue
        x, y = pos[nid]
        kind = _kind(node)
        fill, stroke, text = _node_style(node)
        if node.get("taint_status") == "confirmed" or node.get("taint_confirmed"):
            stroke = "#be123c"
        title, subtitle = _display_parts(node)
        taint = str(node.get("taint_status") or "")
        sink = str(node.get("sink_type") or node.get("sink_category") or "")
        evidence = node.get("evidence") or ""
        sites = node.get("callsites") or []
        site_txt = "; ".join(
            f"{s.get('file')}:{s.get('line')}" for s in sites[:8] if s.get("file")
        )
        hover = (
            f"{node.get('label') or nid} — {evidence}"
            f" | invocation={node.get('invocation_status') or ''}"
            f" taint={taint or 'not_a_sink'} sink={sink or 'none'}"
            f" file={node.get('source_file') or node.get('file') or ''}"
            f":{node.get('source_line') or node.get('line') or ''}"
            f" callsites={site_txt or 'n/a'}"
        )
        rx = 16 if kind in {"database", "vector_db"} else 10
        parts.append(
            f"<g class='wf-node' data-nid='{_e(nid)}' data-kind='{_e(kind)}' "
            f"data-layer='{_e(_layer_name(node))}' "
            f"data-invocation='{_e(node.get('invocation_status') or '')}' "
            f"data-taint='{_e(taint)}' data-sink='{_e(sink)}' "
            f"data-file='{_e(node.get('source_file') or node.get('file') or '')}' "
            f"data-line='{_e(node.get('source_line') or node.get('line') or '')}' "
            f"data-callsites='{_e(site_txt)}' "
            f"tabindex='0' role='button' style='cursor:pointer'>"
            f"<title>{_e(hover)}</title>"
            f"<rect x='{x}' y='{y}' width='{_CARD_W}' height='{_CARD_H}' rx='{rx}' "
            f"fill='{fill}' stroke='{stroke}' stroke-width='1.6'/>"
            f"<text x='{x + _CARD_W / 2}' y='{y + 22}' text-anchor='middle' fill='{text}' "
            f"font-size='12' font-family='ui-sans-serif,system-ui,sans-serif' font-weight='700'>"
            f"{_e(_clip(title, 22))}</text>"
            f"<text x='{x + _CARD_W / 2}' y='{y + 40}' text-anchor='middle' fill='{text}' "
            f"font-size='10' font-family='ui-monospace,Menlo,monospace' opacity='0.85'>"
            f"{_e(_clip(subtitle, 24))}</text>"
            f"</g>"
        )
    ly = height - 18
    lx = float(_PAD)
    parts.append(
        f"<line x1='{_PAD}' y1='{height - legend_h}' x2='{width - _PAD}' "
        f"y2='{height - legend_h}' stroke='#e2e8f0'/>"
        f"<line x1='{lx}' y1='{ly}' x2='{lx + 26}' y2='{ly}' stroke='#6366f1' "
        f"stroke-width='2' marker-end='url(#{_e(marker_id)})'/>"
        f"<text x='{lx + 32}' y='{ly + 4}' fill='#334155' font-size='11' "
        f"font-family='ui-sans-serif,system-ui,sans-serif'>Solid = verified call</text>"
    )
    lx += 168
    parts.append(
        f"<line x1='{lx}' y1='{ly}' x2='{lx + 26}' y2='{ly}' stroke='#94a3b8' "
        f"stroke-width='2' stroke-dasharray='6 4' "
        f"marker-end='url(#{_e(marker_dash)})'/>"
        f"<text x='{lx + 32}' y='{ly + 4}' fill='#334155' font-size='11' "
        f"font-family='ui-sans-serif,system-ui,sans-serif'>Dashed = constructs / registers</text>"
    )
    lx += 228
    parts.append(
        f"<rect x='{lx}' y='{ly - 8}' width='14' height='14' rx='3' "
        f"fill='#ffe4e6' stroke='#e11d48'/>"
        f"<text x='{lx + 20}' y='{ly + 4}' fill='#334155' font-size='11' "
        f"font-family='ui-sans-serif,system-ui,sans-serif'>"
        f"Red box = trust-boundary sinks (LLM, SQL, email, MCP)</text>"
    )
    parts.append("</svg>")
    return "".join(parts)


def _basename(path: object) -> str:
    """Last path segment for card titles."""
    return str(path or "").replace("\\", "/").split("/")[-1]


def _clip_text(text: object, limit: int) -> str:
    """Shorten SVG labels that would overflow the card."""
    s = str(text or "")
    if len(s) <= limit:
        return s
    return s[: max(limit - 1, 1)] + "…"


def _param_from_detail(detail: object) -> str:
    """Extract `param name` from an arg-hop detail string."""
    text = str(detail or "")
    if " param " in text:
        return text.rsplit(" param ", 1)[-1].strip()
    return ""


def _params_in_order(steps: List[Dict[str, Any]]) -> List[str]:
    """Unique incoming parameter names, source → sink."""
    names: List[str] = []
    seen: Set[str] = set()
    for st in steps[1:]:
        name = str(st.get("edge_in") or "")
        if name and name not in {"n/a", "arg"} and name not in seen:
            names.append(name)
            seen.add(name)
    return names


def taint_steps(flow: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Collapse hops into file/function locations with the moving value.

    ``value`` is the data name at that location. ``use`` is the sink
    operation (exec, invoke, …). ``edge_in`` is the parameter on the
    incoming arrow. Source and sink never merge into one box.
    """
    hops = list(flow.get("hops") or [])
    steps: List[Dict[str, Any]] = []

    def merge_or_add(
        role: str,
        file: str,
        func: str,
        line: Any,
        value: str,
        evidence: str,
        use: str = "",
    ) -> None:
        if steps:
            last = steps[-1]
            same = last.get("file") == file and last.get("function") == func
            can_merge = same and (
                last.get("kind") == role
                or (last.get("kind") == "source" and role == "intermediate")
                or (last.get("kind") == "intermediate" and role == "sink")
            )
            if can_merge:
                if role == "sink":
                    last["kind"] = "sink"
                    last["use"] = use or value or last.get("use") or ""
                elif value and (not last.get("value") or role == "intermediate"):
                    last["value"] = value
                if line and not last.get("line"):
                    last["line"] = line
                if evidence:
                    last["evidence"] = evidence
                return
        steps.append({
            "kind": role,
            "file": file,
            "function": func,
            "line": line,
            "value": value,
            "use": use,
            "edge_in": "",
            "label": func or _basename(file),
            "id": f"{role}:{file}::{func}:{line or 'na'}",
            "evidence": evidence,
        })

    if not hops:
        src_val = str(flow.get("taint_kind") or "value")
        sink_op = str(flow.get("sink") or "sink")
        merge_or_add(
            "source",
            str(flow.get("source_file") or ""),
            "",
            flow.get("source_line"),
            src_val,
            "source",
        )
        merge_or_add(
            "sink",
            str(flow.get("sink_file") or ""),
            str(flow.get("sink_function") or ""),
            flow.get("sink_line"),
            src_val,
            "sink",
            use=sink_op,
        )
        if len(steps) == 2:
            steps[1]["edge_in"] = str(flow.get("sink_arg_role") or src_val or "")
        return steps

    pending_param = ""
    for h in hops:
        kind = str(h.get("kind") or "intermediate")
        if kind == "source":
            merge_or_add(
                "source",
                str(h.get("file") or ""),
                str(h.get("function") or ""),
                h.get("line"),
                str(h.get("value") or h.get("detail") or flow.get("taint_kind") or ""),
                str(h.get("detail") or "source"),
            )
        elif kind in {"call", "arg"}:
            pending_param = str(h.get("param") or _param_from_detail(h.get("detail")) or "")
            callee = str(h.get("callee") or "")
            callee_file = str(h.get("callee_file") or "")
            if callee or callee_file:
                merge_or_add(
                    "intermediate",
                    callee_file,
                    callee,
                    h.get("line"),
                    pending_param,
                    str(h.get("detail") or ""),
                )
                if pending_param:
                    steps[-1]["edge_in"] = pending_param
        elif kind == "sink":
            sink_op = str(h.get("value") or h.get("detail") or flow.get("sink") or "")
            arrived = pending_param
            if not arrived and steps:
                arrived = str(steps[-1].get("value") or "")
            merge_or_add(
                "sink",
                str(h.get("file") or flow.get("sink_file") or ""),
                str(h.get("function") or ""),
                h.get("line") or flow.get("sink_line"),
                arrived or sink_op,
                str(h.get("detail") or "sink"),
                use=sink_op,
            )
            if pending_param and steps:
                steps[-1]["edge_in"] = steps[-1].get("edge_in") or pending_param
    return steps


def taint_narrative(flow: Dict[str, Any]) -> str:
    """One demo sentence: this value starts here, is passed as that, is used there."""
    steps = taint_steps(flow)
    if not steps:
        return ""
    src = steps[0]
    sink = steps[-1]
    value = str(src.get("value") or flow.get("taint_kind") or "untrusted value")
    src_file = _basename(src.get("file")) or "the source file"
    sink_file = _basename(sink.get("file")) or "the sink file"
    params = _params_in_order(steps)
    sink_use = str(sink.get("use") or flow.get("sink") or "the sink")
    if len(params) >= 2:
        passed = " then ".join(f"as {p}" for p in params)
        return (
            f"Untrusted value {value} starts in {src_file}, "
            f"is passed {passed}, "
            f"and is used at {sink_use} in {sink_file}."
        )
    if params:
        return (
            f"Untrusted value {value} starts in {src_file}, "
            f"is passed as {params[0]} into {sink_file}, "
            f"and is used at {sink_use}."
        )
    if src_file == sink_file:
        return f"Untrusted value {value} starts in {src_file} and is used at {sink_use}."
    return (
        f"Untrusted value {value} starts in {src_file}, "
        f"moves into {sink_file}, "
        f"and is used at {sink_use}."
    )


def taint_narrative_html(flow: Dict[str, Any]) -> str:
    """HTML caption with identifiers wrapped in ``<code>``."""
    steps = taint_steps(flow)
    if not steps:
        return ""
    src = steps[0]
    sink = steps[-1]
    value = _e(src.get("value") or flow.get("taint_kind") or "untrusted value")
    src_file = _e(_basename(src.get("file")) or "the source file")
    sink_file = _e(_basename(sink.get("file")) or "the sink file")
    params = _params_in_order(steps)
    sink_use = _e(sink.get("use") or flow.get("sink") or "the sink")
    if len(params) >= 2:
        passed = " then ".join(f"as <code>{_e(p)}</code>" for p in params)
        return (
            f"Untrusted value <code>{value}</code> starts in <code>{src_file}</code>, "
            f"is passed {passed}, "
            f"and is used at <code>{sink_use}</code> in <code>{sink_file}</code>."
        )
    if params:
        return (
            f"Untrusted value <code>{value}</code> starts in <code>{src_file}</code>, "
            f"is passed as <code>{_e(params[0])}</code> into <code>{sink_file}</code>, "
            f"and is used at <code>{sink_use}</code>."
        )
    if src_file == sink_file:
        return (
            f"Untrusted value <code>{value}</code> starts in "
            f"<code>{src_file}</code> and is used at <code>{sink_use}</code>."
        )
    return (
        f"Untrusted value <code>{value}</code> starts in <code>{src_file}</code>, "
        f"moves into <code>{sink_file}</code>, "
        f"and is used at <code>{sink_use}</code>."
    )


def taint_flow_svg(flow: Dict[str, Any], *, svg_id: str = "") -> str:
    """Horizontal file-to-file value path. Arrow labels name the moving parameter."""
    cards = taint_steps(flow)
    hidden = 0
    if len(cards) > VISIBLE_CAP:
        hidden = len(cards) - VISIBLE_CAP
        cards = cards[: VISIBLE_CAP - 1] + cards[-1:]

    n = len(cards)
    width = _PAD * 2 + n * _TAINT_CARD_W + max(n - 1, 0) * _TAINT_GAP
    height = _PAD * 2 + _TAINT_CARD_H + (14 if hidden else 0)
    marker_id = f"tarr-{_safe_dom(svg_id or 'taint')}"
    parts = [
        f"<svg class='wf-svg taint-svg' id='{_e(_safe_dom(svg_id or 'taint'))}' role='img' "
        f"viewBox='0 0 {width} {height}' width='{width}' height='{height}' "
        f"xmlns='http://www.w3.org/2000/svg'>",
        f"<defs><marker id='{_e(marker_id)}' markerWidth='7' markerHeight='7' "
        f"refX='6' refY='3.5' orient='auto'>"
        "<polygon points='0 0, 7 3.5, 0 7' fill='#94a3b8'/></marker></defs>",
    ]
    for i, card in enumerate(cards):
        x = _PAD + i * (_TAINT_CARD_W + _TAINT_GAP)
        y = _PAD
        if i < n - 1:
            sx = x + _TAINT_CARD_W
            sy = y + _TAINT_CARD_H / 2
            tx = x + _TAINT_CARD_W + _TAINT_GAP
            nxt = cards[i + 1]
            param = str(nxt.get("edge_in") or "")
            if param in {"n/a", "arg"}:
                param = ""
            arrow = f"as {param}" if param else str(card.get("value") or "")
            parts.append(
                f"<line x1='{sx}' y1='{sy}' x2='{tx}' y2='{sy}' "
                f"stroke='#94a3b8' stroke-width='1.4' marker-end='url(#{_e(marker_id)})'/>"
            )
            if arrow:
                parts.append(
                    f"<text x='{(sx + tx) / 2}' y='{sy - 8}' text-anchor='middle' "
                    f"fill='#1e3a8a' font-size='11' font-family='ui-monospace,Menlo,monospace' "
                    f"font-weight='600'>{_e(_clip_text(arrow, 18))}</text>"
                )
        kind = str(card.get("kind") or "intermediate")
        color = _KIND_COLOR.get(kind, "#64748b")
        title = _KIND_TITLE.get(kind, kind)
        func = str(card.get("function") or card.get("label") or "")
        file_line = _basename(card.get("file"))
        if card.get("line"):
            file_line = f"{file_line}:{card.get('line')}"
        use = str(card.get("use") or "")
        value = str(card.get("value") or "")
        if kind == "sink" and use:
            hero = f"used at {use}"
        else:
            hero = value
        tip = " ".join(p for p in (file_line, func, hero) if p)
        parts.append(
            f"<g class='wf-node' data-nid='{_e(card.get('id'))}' data-kind='{_e(kind)}'>"
            f"<title>{_e(tip)}</title>"
            f"<rect x='{x}' y='{y}' width='{_TAINT_CARD_W}' height='{_TAINT_CARD_H}' rx='8' "
            f"fill='#ffffff' stroke='#d7dee8'/>"
            f"<rect x='{x}' y='{y}' width='6' height='{_TAINT_CARD_H}' rx='3' fill='{color}'/>"
            f"<text x='{x + 12}' y='{y + 16}' fill='#64748b' font-size='9' "
            f"font-family='ui-sans-serif,system-ui,sans-serif' letter-spacing='0.04em'>"
            f"{_e(title.upper())}</text>"
            f"<text x='{x + 12}' y='{y + 34}' fill='#0f172a' font-size='12' "
            f"font-family='ui-sans-serif,system-ui,sans-serif' font-weight='600'>"
            f"{_e(_clip_text(file_line, 28))}</text>"
            f"<text x='{x + 12}' y='{y + 50}' fill='#64748b' font-size='11' "
            f"font-family='ui-monospace,Menlo,monospace'>{_e(_clip_text(func, 26))}</text>"
            f"<text x='{x + 12}' y='{y + 66}' fill='#1e3a8a' font-size='12' "
            f"font-family='ui-monospace,Menlo,monospace' font-weight='600'>"
            f"{_e(_clip_text(hero, 26))}</text>"
            f"</g>"
        )
    if hidden:
        parts.append(
            f"<text x='{_PAD}' y='{height - 2}' fill='#64748b' font-size='10'>"
            f"+{hidden} additional hops in evidence</text>"
        )
    parts.append("</svg>")
    return "".join(parts)


def _inventory_rows(
    components: Optional[Iterable[Any]],
    mcp_servers: Optional[Iterable[Any]],
    graph: Optional[Dict[str, Any]],
) -> List[Dict[str, str]]:
    """Searchable inventory rows. Packages, MCP, and observed call sites stay distinct."""
    rows: List[Dict[str, str]] = []
    seen_pkg: Set[str] = set()
    for c in components or []:
        name = str(getattr(c, "name", "") or "")
        if not name or name in seen_pkg:
            continue
        seen_pkg.add(name)
        props = getattr(c, "properties", None) or {}
        ctype = getattr(getattr(c, "type", None), "value", None) or getattr(c, "type", "") or "library"
        source = str(props.get("source_file") or props.get("declared_in") or "")
        rows.append({
            "id": str(getattr(c, "id", name)),
            "name": name,
            "type": str(ctype),
            "provider": str(props.get("ai_category") or props.get("framework") or ""),
            "model": str(props.get("model") or ""),
            "source": source,
            "evidence": "package inventory",
            "identity": str(getattr(c, "id", name)),
        })
    for s in mcp_servers or []:
        rows.append({
            "id": str(getattr(s, "id", "") or getattr(s, "name", "")),
            "name": str(getattr(s, "name", "") or "mcp"),
            "type": "mcp_server",
            "provider": str(getattr(s, "package", "") or "mcp"),
            "model": "",
            "source": str(getattr(s, "config_path", "") or ""),
            "evidence": "; ".join(getattr(s, "security_findings", None) or []) or "MCP config",
            "identity": str(getattr(s, "id", "") or getattr(s, "name", "")),
        })
    for n in (graph or {}).get("nodes") or []:
        kind = _kind(n)
        if kind == "function":
            continue
        nid = str(n.get("id") or "")
        rows.append({
            "id": nid,
            "name": str(n.get("label") or nid),
            "type": kind,
            "provider": "",
            "model": "",
            "source": _loc(n),
            "evidence": str(n.get("evidence") or n.get("detection_method") or "observed call"),
            "identity": nid,
        })
    return rows


def _nodes_with_outgoing(edges: List[Dict[str, Any]]) -> Set[str]:
    """Node ids that have at least one recorded outgoing edge."""
    return {str(e.get("source") or "") for e in edges if e.get("source")}


_AUXILIARY_ROUTE_MARKERS: Tuple[str, ...] = (
    "/health",
    "/sessions",
    "/docs",
    "/redoc",
    "/openapi",
    "/static",
)


def _route_text(node: Dict[str, Any]) -> str:
    """Route label used only to hide non-AI endpoints from the compact map."""
    return " ".join(
        str(node.get(k) or "")
        for k in ("label", "route_path", "route", "path")
    ).lower()


def _is_auxiliary_route(node: Dict[str, Any], callers: Set[str]) -> bool:
    """True for health/session/static APIs, or any route with no outgoing calls."""
    if _kind(node) != "api_endpoint":
        return False
    text = _route_text(node)
    if any(marker in text for marker in _AUXILIARY_ROUTE_MARKERS):
        return True
    compact = " ".join(text.split())
    if compact in {"get /", "get /index", "/"}:
        return True
    return str(node.get("id") or "") not in callers


def _is_script_node(node: Dict[str, Any]) -> bool:
    """Seed/scripts are not part of the request-time architecture picture."""
    path = str(node.get("file") or node.get("source_file") or "").replace("\\", "/")
    return path.startswith("scripts/") or "/scripts/" in path


def focus_overview_nodes(
    nodes: List[Dict[str, Any]],
    edges: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Keep the request-time map; tuck unused routes and scripts off-canvas."""
    callers = _nodes_with_outgoing(edges)
    keep: List[Dict[str, Any]] = []
    omitted: List[Dict[str, Any]] = []
    keep_ids: Set[str] = set()
    for n in nodes:
        nid = str(n.get("id") or "")
        if _is_auxiliary_route(n, callers) or _is_script_node(n):
            omitted.append(n)
        else:
            keep.append(n)
            keep_ids.add(nid)
    undirected: Dict[str, Set[str]] = defaultdict(set)
    for e in edges:
        src, tgt = str(e.get("source") or ""), str(e.get("target") or "")
        if src in keep_ids and tgt in keep_ids:
            undirected[src].add(tgt)
            undirected[tgt].add(src)
    seeds = [
        str(n.get("id") or "")
        for n in keep
        if _kind(n) in {"api_endpoint", "agent"} or _kind(n) in _CANVAS_KINDS
    ]
    reach: Set[str] = set(seeds)
    stack = list(seeds)
    while stack:
        cur = stack.pop()
        for nxt in undirected.get(cur, []):
            if nxt not in reach:
                reach.add(nxt)
                stack.append(nxt)
    focused: List[Dict[str, Any]] = []
    focused_ids: Set[str] = set()
    for n in keep:
        nid = str(n.get("id") or "")
        if nid in reach or _kind(n) in _CANVAS_KINDS:
            focused.append(n)
            focused_ids.add(nid)
        else:
            omitted.append(n)
    focused_edges = [
        e for e in edges
        if str(e.get("source") or "") in focused_ids
        and str(e.get("target") or "") in focused_ids
    ]
    return focused, omitted, focused_edges


def inter_layer_edges(
    nodes: List[Dict[str, Any]],
    edges: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Overview draws group-to-group calls, not every call inside a box."""
    layer_of = {str(n.get("id") or ""): _layer_name(n) for n in nodes}
    out: List[Dict[str, Any]] = []
    seen: Set[Tuple[str, str]] = set()
    for e in edges:
        src, tgt = str(e.get("source") or ""), str(e.get("target") or "")
        if layer_of.get(src) == layer_of.get(tgt):
            continue
        key = (src, tgt)
        if key in seen:
            continue
        seen.add(key)
        out.append(e)
    return out


def build_overview(
    graph: Optional[Dict[str, Any]],
    components: Optional[Iterable[Any]] = None,
    mcp_servers: Optional[Iterable[Any]] = None,
    *,
    visible_cap: int = ARCH_VISIBLE_CAP,
) -> Dict[str, Any]:
    """
    One application architecture diagram from observed nodes and calls.

    APIs, agents, models, tools, and recorded calls share a single canvas.
    No edges are invented. Isolated functions stay off-canvas as chips.
    Hidden identities are listed, not dropped.
    """
    graph = graph or {"nodes": [], "edges": []}
    all_nodes = list(graph.get("nodes") or [])
    all_edges = list(graph.get("edges") or [])
    by_id = {str(n.get("id")): n for n in all_nodes if n.get("id")}
    original_ids = set(by_id)
    original_edge_keys = {
        (str(e.get("source")), str(e.get("target")), str(e.get("relationship") or e.get("label") or ""))
        for e in all_edges
    }

    linked: Set[str] = set()
    observed_edges: List[Dict[str, Any]] = []
    for e in all_edges:
        src, tgt = str(e.get("source") or ""), str(e.get("target") or "")
        if src in by_id and tgt in by_id and src != tgt:
            linked.add(src)
            linked.add(tgt)
            observed_edges.append(e)

    canvas_nodes: List[Dict[str, Any]] = []
    disconnected: List[Dict[str, Any]] = []
    seen_canvas: Set[str] = set()
    for nid, node in by_id.items():
        if nid in linked or _kind(node) in _CANVAS_KINDS:
            if nid not in seen_canvas:
                canvas_nodes.append(node)
                seen_canvas.add(nid)
        else:
            disconnected.append(node)

    focused, omitted, focused_edges = focus_overview_nodes(canvas_nodes, observed_edges)

    workflows: List[Dict[str, Any]] = []
    if focused:
        vis_ids = pick_visible_ids(focused, focused_edges, cap=visible_cap)
        vis_set = set(vis_ids)
        visible = [n for n in focused if str(n.get("id")) in vis_set]
        hidden = [n for n in focused if str(n.get("id")) not in vis_set]
        vis_edges = inter_layer_edges(
            visible,
            [
                e for e in focused_edges
                if str(e.get("source")) in vis_set and str(e.get("target")) in vis_set
            ],
        )
        workflows.append({
            "id": "wf-app",
            "title": "How requests reach AI and data sinks",
            "visible_node_ids": vis_ids,
            "hidden_node_ids": [str(n.get("id")) for n in hidden],
            "nodes": focused,
            "edges": focused_edges,
            "visible_edges": vis_edges,
            "svg": workflow_svg(visible, vis_edges, svg_id="aitrace-wf-app"),
            "node_count": len(visible),
            "edge_count": len(vis_edges),
        })

    inventory = _inventory_rows(components, mcp_servers, graph)
    types = sorted({r["type"] for r in inventory if r.get("type")})
    return {
        "workflows": workflows,
        "disconnected": disconnected,
        "omitted": omitted,
        "inventory": inventory,
        "inventory_types": types,
        "detailed_graph": graph,
        "visible_cap": visible_cap,
        "original_node_ids": sorted(original_ids),
        "original_edge_keys": [
            {"source": a, "target": b, "relationship": c} for a, b, c in sorted(original_edge_keys)
        ],
        "stats": {
            "workflow_count": len(workflows),
            "disconnected_count": len(disconnected),
            "omitted_count": len(omitted),
            "inventory_count": len(inventory),
            "source_node_count": len(graph.get("nodes") or []),
            "source_edge_count": len(graph.get("edges") or []),
        },
    }
