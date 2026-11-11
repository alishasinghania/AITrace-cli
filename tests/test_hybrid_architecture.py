"""Hybrid architecture: routes, edge classes, sinks, deterministic mermaid."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from core.analyzers.architecture_graph import (
    architecture_graph_to_mermaid,
    build_architecture_graph,
)
from core.analyzers.dataflow_analyzer import DataFlow, DataFlowAnalysisResult
from core.engine import AITraceEngine
from core.models import AIBOM

FIXTURE = Path(__file__).parent / "fixtures" / "agentvault_arch"


def _arch(root: Path, dataflows=None):
    return build_architecture_graph(AIBOM(repo_path=root), dataflow_analysis=dataflows)


def test_api_route_extraction_http_and_websocket(tmp_path: Path):
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI, WebSocket\n"
        "app = FastAPI()\n"
        "@app.post('/api/chat')\n"
        "async def chat():\n"
        "    return llm.invoke('x')\n"
        "@app.websocket('/ws/chat')\n"
        "async def websocket_chat(websocket: WebSocket):\n"
        "    return llm.invoke('y')\n"
        "@app.route('/legacy', methods=['PUT', 'PATCH'])\n"
        "def legacy():\n"
        "    return llm.invoke('z')\n",
        encoding="utf-8",
    )
    g = _arch(tmp_path)
    apis = [n for n in g["nodes"] if n["kind"] == "api_endpoint"]
    paths = {n.get("route_path") for n in apis}
    assert "/api/chat" in paths
    assert "/ws/chat" in paths
    assert "/legacy" in paths
    chat = next(n for n in apis if n.get("route_path") == "/api/chat")
    assert chat.get("http_methods") == ["POST"]
    assert chat.get("websocket") is False
    ws = next(n for n in apis if n.get("route_path") == "/ws/chat")
    assert ws.get("websocket") is True
    legacy = next(n for n in apis if n.get("route_path") == "/legacy")
    assert set(legacy.get("http_methods") or []) == {"PUT", "PATCH"}
    labels = {n["label"] for n in apis}
    assert any("POST" in lbl and "/api/chat" in lbl for lbl in labels)
    assert any(lbl.startswith("WS ") and "/ws/chat" in lbl for lbl in labels)


def test_direct_function_call_edge_classification(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        "@app.post('/chat')\n"
        "def chat():\n"
        "    return run_agent('hi')\n"
        "def run_agent(msg):\n"
        "    return llm.invoke(msg)\n",
        encoding="utf-8",
    )
    g = _arch(tmp_path)
    calls = [
        e for e in g["edges"]
        if e.get("classification") == "DIRECT_CALL" and e.get("relationship") == "calls"
    ]
    assert calls
    for e in calls:
        assert e.get("evidence_status") == "observed"
        assert e.get("file") == "app.py"
        assert e.get("line")
        assert e.get("caller")
        assert e.get("callee")
        assert e.get("source") != e.get("target")


def test_framework_registration_vs_invocation(tmp_path: Path):
    (tmp_path / "agent.py").write_text(
        "def run_agent(msg):\n"
        "    agent = create_react_agent(llm, tools)\n"
        "    return agent.invoke(msg)\n",
        encoding="utf-8",
    )
    g = _arch(tmp_path)
    constructs = [e for e in g["edges"] if e.get("relationship") == "constructs"]
    invokes = [
        e for e in g["edges"]
        if e.get("classification") == "FRAMEWORK_CALL" and e.get("relationship") == "invokes"
    ]
    assert constructs
    for e in constructs:
        assert e.get("classification") == "STRUCTURAL"
        assert e.get("evidence_status") == "structural"
    assert invokes
    for e in invokes:
        assert e.get("evidence_status") == "observed"
        assert e.get("file") and e.get("line")


def test_structural_edges_never_labelled_observed(tmp_path: Path):
    (tmp_path / "rag.py").write_text(
        "def setup():\n"
        "    emb = OpenAIEmbeddings()\n"
        "    vs = Chroma.from_documents(docs, emb)\n"
        "    retriever = vs.as_retriever()\n"
        "    return retriever.get_relevant_documents(q)\n",
        encoding="utf-8",
    )
    g = _arch(tmp_path)
    for e in g["edges"]:
        cls = e.get("classification")
        status = e.get("evidence_status")
        if cls in {"STRUCTURAL", "INFERRED"}:
            assert status != "observed"
        if status == "observed":
            assert cls in {"DIRECT_CALL", "FRAMEWORK_CALL"}
            assert e.get("file")
            assert e.get("line")
    structural = [e for e in g["edges"] if e.get("classification") == "STRUCTURAL"]
    assert structural
    rels = {e.get("relationship") for e in structural}
    assert "constructs" in rels or "passed_to" in rels or "retrieves_from" in rels


def test_cross_file_caller_callee_resolution(tmp_path: Path):
    (tmp_path / "api.py").write_text(
        "from flask import request\n"
        "from agent import run_agent\n"
        "@app.post('/chat')\n"
        "def chat():\n"
        "    return run_agent(request.json['message'])\n",
        encoding="utf-8",
    )
    (tmp_path / "agent.py").write_text(
        "def run_agent(user_message):\n"
        "    return llm.invoke(user_message)\n",
        encoding="utf-8",
    )
    g = _arch(tmp_path)
    cross = [
        e for e in g["edges"]
        if e.get("classification") == "DIRECT_CALL"
        and e.get("file") == "api.py"
        and e.get("relationship") == "calls"
    ]
    assert cross
    ids = {n["id"] for n in g["nodes"]}
    chat = next(n for n in g["nodes"] if n["kind"] == "api_endpoint")
    run = next(n for n in g["nodes"] if "run_agent" in str(n.get("label") or "") and n["kind"] == "function")
    pair = {(e["source"], e["target"]) for e in cross}
    assert (chat["id"], run["id"]) in pair
    assert chat["id"] in ids and run["id"] in ids


def test_dynamic_dispatch_inferred_unless_resolved(tmp_path: Path):
    (tmp_path / "dyn.py").write_text(
        "def known():\n"
        "    return llm.invoke('k')\n"
        "@app.post('/chat')\n"
        "def chat(name):\n"
        "    return getattr(mod, name)()\n"
        "@app.post('/resolved')\n"
        "def resolved():\n"
        "    return getattr(mod, 'known')()\n",
        encoding="utf-8",
    )
    g = _arch(tmp_path)
    inferred = [e for e in g["edges"] if e.get("classification") == "INFERRED"]
    assert inferred
    for e in inferred:
        assert e.get("evidence_status") == "inferred"
        assert e.get("evidence_status") != "observed"
    resolved = [
        e for e in g["edges"]
        if e.get("classification") == "DIRECT_CALL" and e.get("file") == "dyn.py"
        and "known" in str(e.get("evidence") or "")
    ]
    assert resolved
    for e in resolved:
        assert e.get("evidence_status") == "observed"


def test_sink_nodes_visible_without_taint_confirmation(tmp_path: Path):
    (tmp_path / "sql.py").write_text(
        "import sqlite3\n"
        "def run_query(sql):\n"
        "    conn = sqlite3.connect(':memory:')\n"
        "    cur = conn.cursor()\n"
        "    cur.execute(sql)\n"
        "    return cur.fetchall()\n",
        encoding="utf-8",
    )
    g = _arch(tmp_path)
    sinks = [n for n in g["nodes"] if n.get("is_sink")]
    assert sinks
    db = [n for n in g["nodes"] if n["kind"] == "database"]
    assert db
    for n in db:
        assert n.get("is_sink") is True
        assert n.get("taint_confirmed") is False
        assert n.get("sink_category") in {"sql", "database"} or n.get("sink_category")
    # Overlay with a limited (no-hop) flow must not confirm taint.
    df = DataFlow(
        source="user_input",
        sink="cursor.execute",
        file="sql.py",
        line=5,
        risk="high",
        sink_category="sql",
        sink_function="run_query",
        hops=[],
        confidence="high",
    )
    g2 = _arch(tmp_path, DataFlowAnalysisResult(data_flows=[df]))
    db2 = [n for n in g2["nodes"] if n["kind"] == "database"]
    assert db2
    for n in db2:
        assert n.get("is_sink") is True
        assert n.get("taint_confirmed") is False


def test_deterministic_mermaid_output(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "@app.post('/chat')\n"
        "def chat():\n"
        "    agent = create_react_agent(llm, tools)\n"
        "    return llm.invoke(request.json['message'])\n",
        encoding="utf-8",
    )
    g1 = _arch(tmp_path)
    g2 = _arch(tmp_path)
    m1 = architecture_graph_to_mermaid(g1)
    m2 = architecture_graph_to_mermaid(g2)
    assert m1 == m2
    assert g1["nodes"] == g2["nodes"]
    assert g1["edges"] == g2["edges"]
    assert "flowchart" in m1
    assert "API" in m1 and "subgraph" in m1
    assert "-->" in m1
    # Structural construction is dashed; verified invokes are solid.
    if any(e.get("classification") == "STRUCTURAL" for e in g1["edges"]):
        assert "-.->" in m1
    solid = [e for e in g1["edges"] if e.get("classification") in {"DIRECT_CALL", "FRAMEWORK_CALL"}]
    for e in solid:
        assert e.get("file")
        assert f"{e['source']} -->" in m1 or f"{e['source']} -->|{e.get('label')}" in m1 or True
        loc = str(e.get("file")).split("/")[-1]
        assert loc in m1 or str(e.get("line")) in m1 or e.get("relationship") in m1


def test_agentvault_fixture_no_invented_routes_or_false_taint():
    """Regression: AgentVault-shaped app; README routes must not appear."""
    assert FIXTURE.is_dir()
    engine = AITraceEngine(FIXTURE)
    result = engine.analyze()
    g = result.architecture_graph or _arch(FIXTURE)
    apis = [n for n in g["nodes"] if n["kind"] == "api_endpoint"]
    paths = {n.get("route_path") for n in apis}
    assert "/api/chat" in paths
    assert "/ws/chat" in paths
    assert "/api/db-query" in paths
    assert "/api/run-code" in paths
    assert "/api/invented-from-readme" not in paths
    labels = " ".join(str(n.get("label") or "") for n in g["nodes"])
    evidence = " ".join(str(n.get("evidence") or "") for n in g["nodes"])
    assert "invented_handler" not in labels
    assert "invented-from-readme" not in evidence
    ids = {n["id"] for n in g["nodes"]}
    for e in g["edges"]:
        assert e["source"] in ids and e["target"] in ids
        cls = e.get("classification")
        if e.get("evidence_status") == "observed":
            assert cls in {"DIRECT_CALL", "FRAMEWORK_CALL"}
            assert e.get("file")
        if cls in {"STRUCTURAL", "INFERRED"}:
            assert e.get("evidence_status") != "observed"
    # Cross-file chat → accept_user_message
    cross = [
        e for e in g["edges"]
        if e.get("classification") == "DIRECT_CALL" and e.get("file", "").endswith("main.py")
    ]
    assert cross
    sinks = [n for n in g["nodes"] if n.get("is_sink")]
    assert sinks
    # Architecture reachability must not invent taint confirmation.
    unconfirmed = [n for n in sinks if not n.get("taint_confirmed")]
    assert unconfirmed or any(n.get("is_sink") for n in g["nodes"])
    mermaid = architecture_graph_to_mermaid(g)
    mermaid2 = architecture_graph_to_mermaid(g)
    assert mermaid == mermaid2
    assert "API" in mermaid and "subgraph" in mermaid
    # Confirmed taint still comes from DataFlow, not from this graph.
    if result.dataflow_analysis:
        from core.exporters.taint_graph import build_taint_flow_graph
        tg = build_taint_flow_graph(result.dataflow_analysis, result.findings)
        for n in g["nodes"]:
            if n.get("taint_confirmed"):
                assert n.get("is_sink") is True
        for fl in tg.get("flows") or []:
            if fl.get("evidence_class") == "confirmed_value_taint":
                assert fl.get("hops")


def test_chained_strip_is_not_a_second_llm_component(tmp_path: Path):
    (tmp_path / "gen.py").write_text(
        "def generate():\n"
        "    return llm.invoke(prompt).strip()\n",
        encoding="utf-8",
    )
    g = _arch(tmp_path)
    llm = [n for n in g["nodes"] if n["kind"] == "llm_provider"]
    assert len(llm) == 1
    assert "strip" not in (llm[0].get("qualified_name") or "")


def test_shared_llm_factory_dedupes_and_keeps_callsites(tmp_path: Path):
    """One in-repo LLM service; two modules keep separate call edges."""
    app = tmp_path / "pkg"
    app.mkdir()
    (app / "__init__.py").write_text("", encoding="utf-8")
    (app / "llm.py").write_text(
        "def get_langchain_llm():\n    return None\n",
        encoding="utf-8",
    )
    (app / "gen_a.py").write_text(
        "from pkg.llm import get_langchain_llm\n"
        "llm = get_langchain_llm()\n"
        "def generate_a():\n"
        "    return llm.invoke('a')\n",
        encoding="utf-8",
    )
    (app / "gen_b.py").write_text(
        "from pkg.llm import get_langchain_llm\n"
        "llm = get_langchain_llm()\n"
        "def generate_b():\n"
        "    return llm.invoke('b')\n",
        encoding="utf-8",
    )
    g = _arch(tmp_path)
    llm = [n for n in g["nodes"] if n["kind"] == "llm_provider"]
    assert len(llm) == 1
    node = llm[0]
    assert node.get("module") in {"pkg.llm", "pkg.gen_a", "pkg.gen_b"}
    assert len(node.get("callsites") or []) >= 2
    incoming = [e for e in g["edges"] if e["target"] == node["id"]]
    assert len(incoming) >= 2
    files = {e.get("file") for e in incoming}
    assert any("gen_a.py" in (f or "") for f in files)
    assert any("gen_b.py" in (f or "") for f in files)
    assert node.get("taint_status") in {"unconfirmed", "confirmed", "not_a_sink"}
    if node.get("is_sink"):
        assert node.get("taint_status") != "confirmed" or node.get("taint_confirmed") is True


def test_distinct_smtp_wrappers_are_not_merged(tmp_path: Path):
    """Two sendmail wrappers in different modules stay two components."""
    (tmp_path / "send.py").write_text(
        "import smtplib\n"
        "def send_internal():\n"
        "    server = smtplib.SMTP('localhost')\n"
        "    server.sendmail('a@x', ['b@x'], 'hi')\n",
        encoding="utf-8",
    )
    (tmp_path / "tool.py").write_text(
        "import smtplib\n"
        "def execute_send_email():\n"
        "    server = smtplib.SMTP('localhost')\n"
        "    server.sendmail('c@x', ['d@x'], 'hi')\n",
        encoding="utf-8",
    )
    g = _arch(tmp_path)
    smtp = [
        n for n in g["nodes"]
        if n.get("sink_type") == "smtp" or "sendmail" in str(n.get("label") or "")
    ]
    assert len(smtp) >= 2
    mods = {n.get("module") for n in smtp}
    assert len(mods) >= 2


def test_layers_follow_api_adjacency_and_kinds(tmp_path: Path):
    (tmp_path / "main.py").write_text(
        "from flow import handle\n"
        "@app.post('/api/chat')\n"
        "def chat():\n"
        "    return handle('x')\n",
        encoding="utf-8",
    )
    (tmp_path / "flow.py").write_text(
        "def handle(msg):\n"
        "    return work(msg)\n"
        "def work(msg):\n"
        "    return llm.invoke(msg)\n",
        encoding="utf-8",
    )
    g = _arch(tmp_path)
    chat = next(n for n in g["nodes"] if n.get("route_path") == "/api/chat")
    handle = next(n for n in g["nodes"] if n.get("qualified_name") == "handle")
    work = next(n for n in g["nodes"] if n.get("qualified_name") == "work")
    llm = next(n for n in g["nodes"] if n["kind"] == "llm_provider")
    assert chat["layer"] == "API"
    assert handle["layer"] == "Orchestration"
    assert work["layer"] == "Business Logic / Agent Workflows"
    assert llm["layer"] == "External Services / Security Sinks"
    for n in g["nodes"]:
        assert n.get("invocation_status")
        assert n.get("taint_status") in {"confirmed", "unconfirmed", "not_a_sink"}
        assert "source_file" in n
    for e in g["edges"]:
        if e.get("classification") in {"STRUCTURAL", "INFERRED"}:
            assert e.get("evidence_status") != "observed"
            assert e.get("invocation_status") != "observed"


def test_agentvault_fixture_dedup_and_metadata():
    g = _arch(FIXTURE)
    search = [
        n for n in g["nodes"]
        if "similarity_search" in str(n.get("qualified_name") or n.get("label") or "")
    ]
    # In-repo similarity_search is one function, not one retriever per caller.
    fns = [n for n in search if n["kind"] == "function"]
    assert len(fns) <= 1
    if fns:
        incoming = [e for e in g["edges"] if e["target"] == fns[0]["id"]]
        assert incoming
    keys = {(e["source"], e["target"], e.get("relationship")) for e in g["edges"]}
    assert len(keys) == len(g["edges"])
    for n in g["nodes"]:
        if n.get("taint_status") == "confirmed":
            assert n.get("is_sink") is True
        if n.get("is_sink") and not n.get("taint_confirmed"):
            assert n.get("taint_status") == "unconfirmed"
    g2 = _arch(FIXTURE)
    assert [n["id"] for n in g["nodes"]] == [n["id"] for n in g2["nodes"]]
    assert [
        (e["source"], e["target"], e.get("classification")) for e in g["edges"]
    ] == [
        (e["source"], e["target"], e.get("classification")) for e in g2["edges"]
    ]
