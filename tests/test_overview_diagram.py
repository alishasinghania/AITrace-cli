"""Phase 25: compact architecture overview, inventory, finding-centric taint."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from core.analyzers.architecture_graph import build_architecture_graph
from core.engine import AITraceEngine
from core.exporters.html_report import _taint_flow_panel, to_html_report
from core.exporters.overview_diagram import (
    ARCH_VISIBLE_CAP,
    VISIBLE_CAP,
    build_overview,
    connected_components,
    focus_overview_nodes,
    inter_layer_edges,
    pick_visible_ids,
    taint_flow_svg,
    taint_narrative,
    taint_narrative_html,
    taint_steps,
    workflow_svg,
)
from core.exporters.taint_graph import build_taint_flow_graph
from core.models import AIBOM, Component, ComponentType, MCPServer


def _extract_json(html: str, script_id: str) -> dict:
    start = html.find(f"id='{script_id}'")
    assert start != -1, f"missing {script_id}"
    gt = html.find(">", start)
    end = html.find("</script>", gt)
    return json.loads(html[gt + 1 : end])


def test_repeated_calls_keep_distinct_identities(tmp_path: Path):
    """Same LLM in one module is one component; two callsites stay on the edges."""
    (tmp_path / "a.py").write_text(
        "def one(msg):\n"
        "    return llm.invoke(msg)\n"
        "def two(msg):\n"
        "    return llm.invoke(msg)\n",
        encoding="utf-8",
    )
    g = build_architecture_graph(AIBOM(repo_path=tmp_path))
    llm = [n for n in g["nodes"] if n["kind"] == "llm_provider"]
    assert len(llm) == 1
    nid = llm[0]["id"]
    sites = llm[0].get("callsites") or []
    assert len(sites) >= 2
    edges = [e for e in g["edges"] if e["target"] == nid]
    assert len(edges) >= 1
    callsites = []
    for e in edges:
        callsites.extend(e.get("callsites") or [])
    lines = {s.get("line") for s in callsites if s.get("line")}
    assert len(lines) >= 2
    overview = build_overview(g)
    assert nid in overview["original_node_ids"]


def test_same_caller_aggregates_by_identity(tmp_path: Path):
    """Two invokes in one function share the graph identity (kind+file+caller)."""
    (tmp_path / "same.py").write_text(
        "def chat(msg):\n"
        "    llm.invoke(msg)\n"
        "    return llm.invoke(msg)\n",
        encoding="utf-8",
    )
    g = build_architecture_graph(AIBOM(repo_path=tmp_path))
    llm = [n for n in g["nodes"] if n["kind"] == "llm_provider"]
    assert len(llm) == 1
    incoming = [e for e in g["edges"] if e["target"] == llm[0]["id"]]
    sites = []
    for e in incoming:
        sites.extend(e.get("callsites") or [])
    assert len(sites) >= 2
    overview = build_overview(g)
    assert llm[0]["id"] in overview["original_node_ids"]


def test_independent_workflows_and_disconnected_mcp(tmp_path: Path):
    (tmp_path / "chat.py").write_text(
        "from flask import request\n"
        "@app.post('/chat')\n"
        "def chat():\n"
        "    return llm.invoke(request.json['message'])\n",
        encoding="utf-8",
    )
    (tmp_path / "code.py").write_text(
        "from flask import request\n"
        "@app.post('/code')\n"
        "def run_code():\n"
        "    return llm.invoke(request.json['q'])\n",
        encoding="utf-8",
    )
    bom = AIBOM(
        repo_path=tmp_path,
        mcp_servers=[MCPServer(id="mcp-fs", name="filesystem", config_path=".cursor/mcp.json")],
    )
    g = build_architecture_graph(bom)
    comps = connected_components(g)
    assert len(comps) >= 2
    overview = build_overview(g, mcp_servers=bom.mcp_servers)
    assert overview["stats"]["workflow_count"] == 1
    wf = overview["workflows"][0]
    shown = set(wf["visible_node_ids"]) | set(wf["hidden_node_ids"])
    apis = [n for n in g["nodes"] if n["kind"] == "api_endpoint"]
    assert len(apis) >= 2
    assert {n["id"] for n in apis} <= shown
    api_ids = {n["id"] for n in apis}
    for e in wf["edges"]:
        assert e.get("evidence_status") == "observed"
        assert e["source"] in {n["id"] for n in wf["nodes"]}
        assert e["target"] in {n["id"] for n in wf["nodes"]}
        assert not (e["source"] in api_ids and e["target"] in api_ids)
    mcp_ids = {n["id"] for n in g["nodes"] if n["kind"] == "mcp_server"}
    disc_ids = {n["id"] for n in overview["disconnected"]}
    assert mcp_ids
    assert mcp_ids <= shown or mcp_ids <= disc_ids
    svg = wf["svg"]
    assert svg.count("data-nid=") >= 2
    assert "data-layer='API'" in svg
    assert "data-layer='External Services / Security Sinks'" in svg
    for api in apis:
        assert f"data-nid='{api['id']}'" in svg


def test_overview_gitdiagram_layers_show_all_routes(tmp_path: Path):
    """Overview is a layered system map; unused health routes stay off-canvas."""
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI, WebSocket\n"
        "from intake import accept_user_message\n"
        "app = FastAPI()\n"
        "@app.post('/api/chat')\n"
        "async def chat():\n"
        "    return accept_user_message('x')\n"
        "@app.websocket('/ws/chat')\n"
        "async def websocket_chat(websocket: WebSocket):\n"
        "    return accept_user_message('y')\n"
        "@app.post('/api/send-email')\n"
        "async def send_email():\n"
        "    return llm.invoke('z')\n"
        "@app.get('/api/health')\n"
        "async def health():\n"
        "    return {'ok': True}\n",
        encoding="utf-8",
    )
    (tmp_path / "intake.py").write_text(
        "def accept_user_message(msg):\n"
        "    return llm.invoke(msg)\n",
        encoding="utf-8",
    )
    g = build_architecture_graph(AIBOM(repo_path=tmp_path))
    overview = build_overview(g)
    wf = overview["workflows"][0]
    svg = wf["svg"]
    assert "data-layer='API'" in svg
    assert "data-layer='Orchestration'" in svg
    assert "data-layer='External Services / Security Sinks'" in svg
    assert svg.count("class='wf-layer'") >= 3
    apis = [n for n in g["nodes"] if n["kind"] == "api_endpoint"]
    assert len(apis) >= 4
    visible = set(wf["visible_node_ids"])
    omitted_ids = {n["id"] for n in overview.get("omitted") or []}
    health = next(n for n in apis if "health" in str(n.get("label") or "").lower()
                  or "health" in str(n.get("route_path") or "").lower())
    assert health["id"] not in visible
    assert f"data-nid='{health['id']}'" not in svg
    assert health["id"] in omitted_ids
    for api in apis:
        if api["id"] == health["id"]:
            continue
        assert api["id"] in visible
        assert f"data-nid='{api['id']}'" in svg
    assert "POST /api/chat" in svg or "api/chat" in svg
    assert "WS" in svg or "/ws/chat" in svg
    assert "Solid = verified call" in svg
    assert "trust-boundary sinks" in svg


def test_large_graph_bounded_layout_and_readable_labels():
    nodes = [
        {"id": f"n{i}", "kind": "function" if i else "api_endpoint", "label": f"handler_{i}" * 3,
         "file": "app.py", "line": i + 1, "evidence": f"call {i}"}
        for i in range(24)
    ]
    nodes.append({"id": "llm", "kind": "llm_provider", "label": "LangChain LLM invoke",
                  "file": "app.py", "line": 99, "evidence": "call llm"})
    edges = [{"source": f"n{i}", "target": f"n{i+1}", "relationship": "calls",
              "evidence_status": "observed"} for i in range(23)]
    edges.append({"source": "n23", "target": "llm", "relationship": "invokes",
                  "evidence_status": "observed"})
    g = {"nodes": nodes, "edges": edges, "stats": {"node_count": 25, "edge_count": 24}}
    overview = build_overview(g, visible_cap=VISIBLE_CAP)
    assert overview["workflows"]
    wf = overview["workflows"][0]
    assert len(wf["visible_node_ids"]) <= VISIBLE_CAP
    assert len(wf["hidden_node_ids"]) >= 24 - VISIBLE_CAP
    svg = wf["svg"]
    assert "viewBox=" in svg
    assert "…" in svg or "handler_0" in svg
    width = int(svg.split("width='")[1].split("'")[0])
    assert width <= 1800
    vis = pick_visible_ids(nodes, edges, cap=8)
    assert vis[0] == "n0"
    assert "llm" in vis
    one = build_overview(g, visible_cap=ARCH_VISIBLE_CAP)
    assert one["stats"]["workflow_count"] == 1


def test_node_edge_evidence_preserved(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "@app.post('/chat')\n"
        "def chat():\n"
        "    return llm.invoke(request.json['message'])\n",
        encoding="utf-8",
    )
    g = build_architecture_graph(AIBOM(repo_path=tmp_path))
    overview = build_overview(g)
    src_ids = {n["id"] for n in g["nodes"]}
    assert set(overview["original_node_ids"]) == src_ids
    src_edges = {
        (e["source"], e["target"], e.get("relationship") or e.get("label") or "")
        for e in g["edges"]
    }
    ov_edges = {
        (e["source"], e["target"], e["relationship"])
        for e in overview["original_edge_keys"]
    }
    assert ov_edges == src_edges
    for wf in overview["workflows"]:
        for n in wf["nodes"]:
            assert n.get("evidence") or n.get("detection_method")


def test_finding_specific_taint_visualization(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "@app.post('/chat')\n"
        "def chat():\n"
        "    llm.invoke(request.json['message'])\n",
        encoding="utf-8",
    )
    result = AITraceEngine(tmp_path).analyze()
    html = to_html_report(result, tmp_path)
    assert "Taint paths" in html
    assert "confirmed attack path" in html.lower() or "Confirmed taint paths" in html
    assert "taint-flow-panel is-active" in html
    assert "taint-story" in html
    assert "taint-path-table" in html
    assert "Each box is a location" in html
    assert "Combined hop diagram" not in html
    assert "AI Data Flows" not in html
    assert "not value-taint" in html or "Call-graph reachability" in html or "value-taint" in html
    assert "All flows" not in html
    tg = build_taint_flow_graph(result.dataflow_analysis, result.findings)
    assert tg["flows"]
    svg = taint_flow_svg(tg["flows"][0], svg_id="t0")
    assert ">SOURCE</text>" in svg or ">SINK</text>" in svg
    assert "data-nid=" in svg
    if tg["flows"][0].get("finding_ids"):
        assert "data-show-taint-flow=" in html


def test_inventory_filter_and_offline_report(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("openai==1.0.0\n", encoding="utf-8")
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "@app.post('/chat')\n"
        "def chat():\n"
        "    llm.invoke(request.json['message'])\n",
        encoding="utf-8",
    )
    result = AITraceEngine(tmp_path).analyze()
    html = to_html_report(result, tmp_path)
    assert "AI Application Overview" in html
    assert "id='ai-overview'" in html
    assert "id='architecture-graph'" in html
    assert "id='ai-components'" in html
    assert "data-inv-search" in html
    assert "data-inv-filter" in html
    assert "data-overview-tab='arch'" in html
    assert "data-overview-tab='inv'" in html
    assert "cytoscape" not in html.lower()
    assert "unpkg.com" not in html
    assert "fonts.googleapis" not in html
    assert "--bg:#f4f6f8" in html
    overview = _extract_json(html, "aitrace-overview-data")
    assert "stats" in overview
    assert html.count("<svg") >= 1
    # Inventory includes both packages and observed call sites.
    assert "openai" in html.lower()
    assert "llm_provider" in html or "LLM" in html


def test_workflow_svg_does_not_invent_edges():
    nodes = [
        {"id": "a", "kind": "api_endpoint", "label": "chat", "file": "a.py", "line": 1},
        {"id": "b", "kind": "llm_provider", "label": "invoke", "file": "a.py", "line": 2},
        {"id": "c", "kind": "tool", "label": "repl", "file": "b.py", "line": 3},
    ]
    edges = [{"source": "a", "target": "b", "relationship": "invokes", "evidence_status": "observed"}]
    svg = workflow_svg(nodes[:2], edges, svg_id="only-ab")
    assert "data-nid='a'" in svg
    assert "data-nid='b'" in svg
    # Isolated tool must not appear unless passed as a visible node.
    assert "data-nid='c'" not in svg
    overview = build_overview({"nodes": nodes, "edges": edges})
    shown = set()
    for wf in overview["workflows"]:
        shown.update(wf["visible_node_ids"])
        shown.update(wf["hidden_node_ids"])
        assert all(e["source"] != "c" and e["target"] != "c" for e in wf["edges"])
    disc_ids = {n["id"] for n in overview["disconnected"]}
    assert "c" in shown or "c" in disc_ids


def test_component_package_inventory_rows():
    comps = [
        Component(
            id="pkg:pypi/openai@1",
            name="openai",
            type=ComponentType.LIBRARY,
            version="1",
            properties={"ai_category": "llm_sdk"},
        )
    ]
    overview = build_overview({"nodes": [], "edges": []}, components=comps)
    names = [r["name"] for r in overview["inventory"]]
    assert "openai" in names
    assert overview["inventory"][0]["provider"] == "llm_sdk"


def test_taint_cards_name_the_moving_value():
    """Boxes are files; the arrow is the parameter the value travels as."""
    flow = {
        "taint_kind": "payload",
        "sink": "exec",
        "sink_arg_role": "n/a",
        "hops": [
            {
                "kind": "source",
                "file": "app/code_flow/compose.py",
                "function": "compose_code_answer",
                "line": 8,
                "detail": "llm_output",
                "value": "llm_output",
            },
            {
                "kind": "call",
                "file": "app/code_flow/compose.py",
                "function": "compose_code_answer",
                "param": "code",
                "callee": "run_generated_code",
                "callee_file": "app/code_flow/execute.py",
                "detail": "arg -> run_generated_code param code",
                "value": "code",
            },
            {
                "kind": "sink",
                "file": "app/code_flow/execute.py",
                "function": "run_generated_code",
                "line": 9,
                "detail": "exec",
                "value": "exec",
            },
        ],
    }
    steps = taint_steps(flow)
    assert [s["kind"] for s in steps] == ["source", "sink"]
    assert steps[0]["function"] == "compose_code_answer"
    assert steps[0]["value"] == "llm_output"
    assert steps[1]["function"] == "run_generated_code"
    assert steps[1]["edge_in"] == "code"
    assert steps[1]["use"] == "exec"
    svg = taint_flow_svg(flow, svg_id="rce")
    assert "compose_code_answer" in svg
    assert "run_generated_code" in svg
    assert "compose.py:8" in svg
    assert "execute.py:9" in svg
    assert "llm_output" in svg
    assert "used at exec" in svg
    assert "as code" in svg
    assert "value: llm_output" not in svg
    assert "compose.py::compo…" not in svg
    story = taint_narrative(flow)
    assert "llm_output" in story
    assert "passed as code" in story
    assert "compose.py" in story
    assert "execute.py" in story
    assert "used at exec" in story
    html_story = taint_narrative_html(flow)
    assert "<code>llm_output</code>" in html_story
    assert "<code>code</code>" in html_story
    panel = _taint_flow_panel(flow, active=True)
    assert "taint-story" in panel
    assert "taint-path-table" in panel
    assert "passed as code, used at exec" in panel
    assert "compose.py:8" in panel
    assert "compose_code_answer" in panel
    assert "Each box is a location" in panel


def test_taint_narrative_lists_each_rename():
    """A three-file path names every parameter the value is passed as."""
    flow = {
        "sink": "os.system",
        "hops": [
            {
                "kind": "source",
                "file": "app.py",
                "function": "handler",
                "line": 4,
                "value": "user_input",
            },
            {
                "kind": "call",
                "file": "app.py",
                "function": "handler",
                "param": "question",
                "callee": "compose_code_answer",
                "callee_file": "compose.py",
                "value": "question",
            },
            {
                "kind": "call",
                "file": "compose.py",
                "function": "compose_code_answer",
                "param": "code",
                "callee": "run_generated_code",
                "callee_file": "execute.py",
                "value": "code",
            },
            {
                "kind": "sink",
                "file": "execute.py",
                "function": "run_generated_code",
                "line": 3,
                "value": "os.system",
            },
        ],
    }
    steps = taint_steps(flow)
    assert [s["kind"] for s in steps] == ["source", "intermediate", "sink"]
    assert [s.get("edge_in") for s in steps] == ["", "question", "code"]
    story = taint_narrative(flow)
    assert "as question then as code" in story
    assert "os.system" in story
    assert "execute.py" in story
    svg = taint_flow_svg(flow, svg_id="rce3")
    assert "as question" in svg
    assert "as code" in svg
    assert "used at os.system" in svg
    assert "compose_code_answer" in svg


def test_inter_layer_edges_skip_calls_inside_a_box():
    """Compact overview draws group-to-group arrows, not every call in a layer."""
    nodes = [
        {"id": "api", "kind": "api_endpoint", "label": "POST /chat", "layer": "API"},
        {"id": "a", "kind": "function", "label": "compose",
         "layer": "Business Logic / Agent Workflows"},
        {"id": "b", "kind": "function", "label": "send",
         "layer": "Business Logic / Agent Workflows"},
        {"id": "llm", "kind": "llm_provider", "label": "invoke",
         "layer": "External Services / Security Sinks"},
    ]
    edges = [
        {"source": "api", "target": "a", "relationship": "calls"},
        {"source": "a", "target": "b", "relationship": "calls"},
        {"source": "b", "target": "llm", "relationship": "invokes"},
    ]
    crossed = inter_layer_edges(nodes, edges)
    pairs = {(e["source"], e["target"]) for e in crossed}
    assert ("api", "a") in pairs
    assert ("b", "llm") in pairs
    assert ("a", "b") not in pairs


def test_overview_omits_idle_health_and_seed_scripts(tmp_path: Path):
    """Health routes and scripts/ stay off the compact map but remain in the graph."""
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "@app.post('/chat')\n"
        "def chat():\n"
        "    return llm.invoke(request.json['q'])\n"
        "@app.get('/api/health')\n"
        "def health():\n"
        "    return {'ok': True}\n",
        encoding="utf-8",
    )
    g = build_architecture_graph(AIBOM(repo_path=tmp_path))
    overview = build_overview(g)
    wf = overview["workflows"][0]
    svg = wf["svg"]
    assert "/api/health" not in svg
    assert "GET /api/health" not in svg
    assert "/chat" in svg or "chat" in svg
    omitted_labels = " ".join(str(n.get("label") or "") for n in overview["omitted"]).lower()
    assert "health" in omitted_labels
    assert any(n["id"] in overview["original_node_ids"] for n in overview["omitted"])

    nodes = [
        {"id": "seed", "kind": "function", "label": "main", "file": "scripts/seed_database.py"},
        {"id": "sql", "kind": "database", "label": "executescript",
         "file": "scripts/seed_database.py"},
        {"id": "api", "kind": "api_endpoint", "label": "POST /chat"},
        {"id": "llm", "kind": "llm_provider", "label": "invoke"},
    ]
    edges = [
        {"source": "seed", "target": "sql", "relationship": "invokes"},
        {"source": "api", "target": "llm", "relationship": "invokes"},
    ]
    keep, omitted, focused_edges = focus_overview_nodes(nodes, edges)
    assert {n["id"] for n in omitted} == {"seed", "sql"}
    assert {n["id"] for n in keep} == {"api", "llm"}
    assert all(e["source"] != "seed" and e["target"] != "sql" for e in focused_edges)

    session_nodes = [
        {"id": "sess", "kind": "api_endpoint", "label": "GET /api/sessions/{id}/history"},
        {"id": "hist", "kind": "function", "label": "get_history",
         "layer": "Business Logic / Agent Workflows"},
        {"id": "root", "kind": "api_endpoint", "label": "GET /"},
        {"id": "chat", "kind": "api_endpoint", "label": "POST /api/chat"},
        {"id": "llm2", "kind": "llm_provider", "label": "invoke"},
    ]
    session_edges = [
        {"source": "sess", "target": "hist", "relationship": "calls"},
        {"source": "chat", "target": "llm2", "relationship": "invokes"},
    ]
    keep2, omitted2, _ = focus_overview_nodes(session_nodes, session_edges)
    omitted2_ids = {n["id"] for n in omitted2}
    keep2_ids = {n["id"] for n in keep2}
    assert "sess" in omitted2_ids
    assert "root" in omitted2_ids
    assert "hist" in omitted2_ids
    assert "chat" in keep2_ids
    assert "llm2" in keep2_ids
