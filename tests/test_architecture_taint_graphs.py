"""Phase 5: evidence-backed architecture and taint-flow graphs."""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from core.analyzers.architecture_graph import build_architecture_graph
from core.analyzers.crossfile_taint import TaintPath
from core.analyzers.dataflow_analyzer import DataFlow, DataFlowAnalysisResult, analyze_dataflows
from core.engine import AITraceEngine
from core.exporters.html_report import to_html_report
from core.exporters.taint_graph import build_taint_flow_graph
from core.models import AIBOM, MCPServer


def _arch(root: Path, aibom: AIBOM | None = None, dataflows=None):
    bom = aibom or AIBOM(repo_path=root)
    return build_architecture_graph(bom, dataflow_analysis=dataflows)


def test_api_agent_llm_architecture(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "@app.post('/chat')\n"
        "def chat():\n"
        "    return run_agent(request.json['message'])\n"
        "def run_agent(user_message):\n"
        "    agent = create_react_agent(llm, tools)\n"
        "    return llm.invoke(user_message)\n",
        encoding="utf-8",
    )
    g = _arch(tmp_path)
    kinds = {n["kind"] for n in g["nodes"]}
    assert "api_endpoint" in kinds
    assert "agent" in kinds
    assert "llm_provider" in kinds
    ids = {n["id"] for n in g["nodes"]}
    for e in g["edges"]:
        assert e["source"] in ids and e["target"] in ids
        assert e.get("evidence_status") == "observed"


def test_prompt_builder_distinct_from_llm(tmp_path: Path):
    (tmp_path / "prompts.py").write_text(
        "def build_prompt(msg):\n"
        "    return ChatPromptTemplate.from_template('{x}').format(x=msg)\n"
        "def ask(msg):\n"
        "    p = build_prompt(msg)\n"
        "    return llm.invoke(p)\n",
        encoding="utf-8",
    )
    g = _arch(tmp_path)
    kinds = {n["kind"] for n in g["nodes"]}
    assert "prompt_builder" in kinds
    assert "llm_provider" in kinds
    prompt_ids = [n["id"] for n in g["nodes"] if n["kind"] == "prompt_builder"]
    llm_ids = [n["id"] for n in g["nodes"] if n["kind"] == "llm_provider"]
    assert prompt_ids and llm_ids and set(prompt_ids).isdisjoint(set(llm_ids))


def test_rag_retriever_vector_store_edge(tmp_path: Path):
    (tmp_path / "rag.py").write_text(
        "def setup():\n"
        "    emb = OpenAIEmbeddings()\n"
        "    vs = Chroma.from_documents(docs, emb)\n"
        "    retriever = vs.as_retriever()\n"
        "    return retriever.get_relevant_documents(q)\n",
        encoding="utf-8",
    )
    g = _arch(tmp_path)
    kinds = {n["kind"] for n in g["nodes"]}
    assert "embedding_model" in kinds
    assert "vector_db" in kinds
    assert "retriever" in kinds
    rels = {e.get("relationship") for e in g["edges"]}
    assert "passed_to" in rels or "retrieves_from" in rels or "invokes" in rels


def test_mcp_component_from_config(tmp_path: Path):
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    bom = AIBOM(
        repo_path=tmp_path,
        mcp_servers=[
            MCPServer(id="mcp-fs", name="filesystem", config_path=".cursor/mcp.json"),
        ],
    )
    g = _arch(tmp_path, bom)
    mcp = [n for n in g["nodes"] if n["kind"] == "mcp_server"]
    assert len(mcp) == 1
    assert mcp[0]["file"] == ".cursor/mcp.json"
    assert mcp[0]["detection_method"] == "mcp_config"


def test_no_ai_components(tmp_path: Path):
    (tmp_path / "hello.py").write_text("def main():\n    print('hi')\n", encoding="utf-8")
    g = _arch(tmp_path)
    assert g["nodes"] == []
    assert g["edges"] == []
    html = to_html_report(
        SimpleNamespace(
            aibom=AIBOM(repo_path=tmp_path),
            findings=[],
            architecture_result=None,
            architecture_graph=g,
            dataflow_analysis=DataFlowAnalysisResult(),
            policy_report=None,
            sensitive_exposures=None,
            model_supply_chain=None,
            prompt_injection_risks=None,
            llm_usage=None,
            repo_type="application",
            attack_path_findings=None,
            pattern_analysis=None,
            crossfile_taint=None,
            llm_verification=None,
        ),
        tmp_path,
    )
    assert "No AI architecture components" in html


def test_direct_request_to_llm_taint_graph(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "def chat():\n"
        "    llm.invoke(request.json['message'])\n",
        encoding="utf-8",
    )
    analysis = analyze_dataflows(tmp_path)
    result = AITraceEngine(tmp_path).analyze()
    g = build_taint_flow_graph(analysis, result.findings)
    assert g["flow_count"] >= 1
    flow = next(f for f in g["flows"] if f["sink_category"] == "llm")
    assert flow["taint_kind"] == "payload"
    assert "FLOW-LLM" in flow["finding_ids"]
    assert flow["source_line"] is not None
    assert flow["sink_line"] is not None


def test_cross_file_hops_in_taint_graph(tmp_path: Path):
    (tmp_path / "api.py").write_text(
        "from flask import request\n"
        "from agent import run_agent\n"
        "def chat():\n"
        "    return run_agent(request.json['message'])\n",
        encoding="utf-8",
    )
    (tmp_path / "agent.py").write_text(
        "def run_agent(user_message):\n"
        "    return llm.invoke(user_message)\n",
        encoding="utf-8",
    )
    analysis = analyze_dataflows(tmp_path)
    g = build_taint_flow_graph(analysis)
    flow = next(f for f in g["flows"] if f["sink_category"] == "llm")
    kinds = {h.get("kind") for h in flow["hops"]}
    assert "call" in kinds or any("arg" in str(h) for h in flow["hops"])
    assert flow["evidence_class"] == "confirmed_value_taint"


def test_source_sink_only_when_hops_missing():
    df = DataFlow(
        source="user_input",
        sink="llm.invoke",
        file="app.py",
        line=4,
        risk="high",
        source_line=2,
        source_file="app.py",
        sink_category="llm",
        taint_kind="payload",
        hops=[],
    )
    g = build_taint_flow_graph(DataFlowAnalysisResult(data_flows=[df]))
    assert g["flow_count"] == 1
    assert g["flows"][0]["evidence_class"] == "limited_source_sink"
    assert len(g["nodes"]) == 2
    assert g["flows"][0]["hops"] == []


def test_lookup_identifier_not_drawn_as_payload():
    df = DataFlow(
        source="user_input",
        sink="llm.invoke",
        file="app.py",
        line=9,
        risk="high",
        source_line=3,
        source_file="app.py",
        sink_category="llm",
        taint_kind="identifier",
        hops=["app.py::chat:3 source user_input", "app.py::chat:9 sink llm.invoke"],
        confidence="high",
    )
    g = build_taint_flow_graph(DataFlowAnalysisResult(data_flows=[df]))
    assert g["flows"][0]["taint_kind"] == "identifier"
    assert g["flows"][0]["evidence_class"] == "value_taint:identifier"
    assert g["edges"][0]["taint_kind"] == "identifier"


def test_unresolved_wrapper_not_confirmed_taint(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "def chat():\n"
        "    y = unknown(request.json['message'])\n"
        "    llm.invoke(y)\n",
        encoding="utf-8",
    )
    analysis = analyze_dataflows(tmp_path)
    g = build_taint_flow_graph(analysis)
    payload = [
        f for f in g["flows"]
        if f["sink_category"] == "llm" and f["taint_kind"] == "payload"
    ]
    for f in payload:
        joined = " ".join(h.get("detail", "") for h in f["hops"])
        assert "unknown" not in joined


def test_bfs_path_not_promoted_to_taint_graph():
    path = TaintPath(
        source_key="a.py::src",
        sink_key="b.py::sink",
        sink_type="llm",
        hops=["a.py::src", "b.py::sink"],
        hop_count=1,
        confirmed=False,
        partial=True,
        vulnerability_type="prompt_injection",
    )
    xt = SimpleNamespace(taint_paths=[path])
    g = build_taint_flow_graph(DataFlowAnalysisResult(data_flows=[]), crossfile_taint=xt)
    assert g["flow_count"] == 0
    assert g["flows"] == []
    assert g["structural_reachability"]
    assert g["structural_reachability"][0]["not_value_taint"] is True


def test_http_body_not_ssrf_in_taint_graph(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "import requests\n"
        "def chat():\n"
        "    msg = request.json['message']\n"
        "    requests.post('https://api.example/x', json=msg)\n",
        encoding="utf-8",
    )
    analysis = analyze_dataflows(tmp_path)
    result = AITraceEngine(tmp_path).analyze()
    g = build_taint_flow_graph(analysis, result.findings)
    body = [f for f in g["flows"] if f.get("sink_arg_role") == "body"]
    assert body
    for f in body:
        assert f["ssrf_candidate"] is False
        assert "FLOW-HTTP" not in f["finding_ids"]


def test_one_source_two_sinks_are_separate_flows(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "import os\n"
        "def chat():\n"
        "    msg = request.json['message']\n"
        "    llm.invoke(msg)\n"
        "    os.system('echo ' + msg)\n",
        encoding="utf-8",
    )
    g = build_taint_flow_graph(analyze_dataflows(tmp_path))
    cats = {f["sink_category"] for f in g["flows"]}
    assert "llm" in cats
    assert "rce" in cats
    assert g["flow_count"] >= 2
    assert g["unique_sink_count"] >= 2


def test_missing_line_information():
    df = DataFlow(
        source="user_input",
        sink="llm.invoke",
        file="app.py",
        line=None,
        risk="high",
        source_line=None,
        source_file="app.py",
        sink_category="llm",
        taint_kind="payload",
        hops=["app.py::chat source user_input", "app.py::chat sink llm.invoke"],
    )
    g = build_taint_flow_graph(DataFlowAnalysisResult(data_flows=[df]))
    assert g["flows"][0]["source_line"] is None
    assert g["flows"][0]["sink_line"] is None
    for n in g["nodes"]:
        assert n.get("line") in (None, )


def test_findings_without_architecture_edges(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        "API_KEY = 'sk-abcdefghijklmnopqrstuvwx'\n",
        encoding="utf-8",
    )
    result = AITraceEngine(tmp_path).analyze()
    g = result.architecture_graph or _arch(tmp_path)
    assert g.get("edges") == [] or g.get("stats", {}).get("edge_count", 0) == 0
    assert any(f.id == "PAT-010" or "credential" in (f.title or "").lower() for f in result.findings) or result.findings


def test_graph_references_are_real_entities(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "@app.post('/x')\n"
        "def chat():\n"
        "    llm.invoke(request.json['message'])\n",
        encoding="utf-8",
    )
    analysis = analyze_dataflows(tmp_path)
    result = AITraceEngine(tmp_path).analyze()
    arch = result.architecture_graph
    ids = {n["id"] for n in arch["nodes"]}
    for e in arch["edges"]:
        assert e["source"] in ids
        assert e["target"] in ids
    tg = build_taint_flow_graph(analysis, result.findings)
    nids = {n["id"] for n in tg["nodes"]}
    for e in tg["edges"]:
        assert e["source"] in nids
        assert e["target"] in nids
    known = {f.id for f in result.findings}
    for fl in tg["flows"]:
        for fid in fl["finding_ids"]:
            assert fid in known


def test_html_contains_both_graphs_and_fallback(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "@app.post('/chat')\n"
        "def chat():\n"
        "    llm.invoke(request.json['message'])\n",
        encoding="utf-8",
    )
    result = AITraceEngine(tmp_path).analyze()
    html = to_html_report(result, tmp_path)
    assert "AI application architecture" in html
    assert "Taint-flow graph" in html
    assert "aitrace-arch-data" in html
    assert "aitrace-taint-data" in html
    assert "graph-fallback" in html
    assert "aitrace-arch-svg" in html
    assert "Security findings" in html


def test_cyclic_architecture_does_not_hang(tmp_path: Path):
    (tmp_path / "loop.py").write_text(
        "def a(x):\n"
        "    return b(x)\n"
        "def b(x):\n"
        "    return a(llm.invoke(x))\n",
        encoding="utf-8",
    )
    g = _arch(tmp_path)
    ids = {n["id"] for n in g["nodes"]}
    for e in g["edges"]:
        assert e["source"] in ids
        assert e["target"] in ids
    mermaid = __import__(
        "core.analyzers.architecture_graph", fromlist=["architecture_graph_to_mermaid"]
    ).architecture_graph_to_mermaid(g)
    assert "flowchart" in mermaid
