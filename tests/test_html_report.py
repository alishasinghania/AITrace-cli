"""HTML report: AI Data Flows table uses taint DataFlow only."""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from core.analyzers.dataflow_analyzer import analyze_dataflows
from core.exporters.component_diagram import to_ai_component_mermaid
from core.exporters.html_report import (
    _count_dataflows,
    _dataflow_section,
    _dataflow_table_row,
)
from core.exporters.taint_diagram import taint_flows_to_mermaid
from core.exporters.risk_report import to_risk_report_json, to_risk_report_markdown
from core.models import AIBOM


def test_taint_flow_row_has_source_sink_location():
    df = SimpleNamespace(
        source="user_input",
        sink="LangChain LLM invoke",
        file="app.py",
        line=12,
        risk="high",
        source_file="app.py",
        source_line=10,
        sink_category="llm",
        hops=["app.py::handler:10 source user_input", "app.py::handler:12 sink LangChain LLM invoke"],
        sanitized=False,
        confidence="high",
    )
    risk, source, sink, cat, loc, trace, notes = _dataflow_table_row(df)
    assert risk == "high"
    assert source == "user_input"
    assert "LLM" in sink
    assert cat == "llm"
    assert "app.py:10" in loc
    assert "app.py:12" in loc
    assert "source user_input" in trace
    assert "sink LangChain LLM invoke" in trace
    assert "confidence:high" in notes


def test_missing_hops_render_placeholder():
    df = SimpleNamespace(
        source="user_input",
        sink="os.system",
        file="tools.py",
        line=3,
        risk="high",
        sink_category="rce",
    )
    row = _dataflow_table_row(df)
    assert row[5] == "<div class='path-chain'>—</div>"


def test_architecture_graphs_are_not_used_as_taint_rows():
    graph = SimpleNamespace(
        flow_type="Direct LLM",
        nodes=[
            SimpleNamespace(id="a", label="Prompt Builder", kind="prompt_builder"),
            SimpleNamespace(id="b", label="LLM Inference", kind="llm_inference"),
        ],
        edges=[],
        example_files=["langfail/agent/llm.py"],
        occurrence_count=4,
    )
    empty_taint = SimpleNamespace(data_flows=[])
    html = _dataflow_section(empty_taint, [graph])
    assert html == ""
    assert _count_dataflows(empty_taint, [graph]) == 0


def test_empty_taint_hides_section():
    html = _dataflow_section(SimpleNamespace(data_flows=[]), [])
    assert html == ""
    assert _count_dataflows(SimpleNamespace(data_flows=[]), []) == 0


def test_html_and_markdown_show_real_multifile_hops(tmp_path: Path):
    """Rendered trace comes from analyze_dataflows hops, not AIBOM graphs."""
    (tmp_path / "app.py").write_text(
        "from service import process\n"
        "def handler(request):\n"
        "    value = request.json['message']\n"
        "    return process(value)\n",
        encoding="utf-8",
    )
    (tmp_path / "service.py").write_text(
        "def process(text):\n"
        "    return llm.invoke(text)\n",
        encoding="utf-8",
    )
    result = analyze_dataflows(tmp_path)
    assert result.data_flows
    flow = result.data_flows[0]
    assert flow.hops
    assert any("service.py::process" in h for h in flow.hops)

    html = _dataflow_section(result, [])
    assert "service.py" in html
    assert "app.py" in html
    assert "user_input" in html
    assert "llm" in html.lower()
    html_plain = html.replace("&gt;", ">").replace("&lt;", "<").replace("&amp;", "&")
    for hop in flow.hops:
        assert hop in html_plain

    md = to_risk_report_markdown(AIBOM(repo_path=tmp_path), None, dataflow_analysis=result)
    assert "## AI Data Flow Analysis" in md
    assert "Trace" in md
    assert "user_input" in md
    assert any("service.py::process" in line for line in md.splitlines())
    graph = SimpleNamespace(
        flow_type="Direct LLM",
        nodes=[SimpleNamespace(id="a", label="Prompt Builder", kind="prompt_builder")],
        edges=[],
        example_files=["fabricated.py"],
        occurrence_count=9,
    )
    html2 = _dataflow_section(result, [graph])
    assert "fabricated.py" not in html2
    assert "class='mermaid'" in html
    assert "service.py::process" in html_plain or "process" in html


def test_incomplete_analysis_visible_in_html():
    analysis = SimpleNamespace(
        data_flows=[
            SimpleNamespace(
                source="user_input",
                sink="LangChain LLM invoke",
                file="app.py",
                line=3,
                risk="high",
                sink_category="llm",
                hops=[],
                confidence="may",
            )
        ],
        incomplete=True,
        incomplete_reasons=["context_cap"],
    )
    html = _dataflow_section(analysis, [])
    assert "Analysis incomplete" in html
    assert "context_cap" in html
    assert "full coverage" in html


def test_json_taint_count_not_architecture_graphs(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        "def handler(request):\n"
        "    llm.invoke(request.json['message'])\n",
        encoding="utf-8",
    )
    result = analyze_dataflows(tmp_path)
    report = to_risk_report_json(
        AIBOM(repo_path=tmp_path),
        None,
        dataflow_analysis=result,
    )
    assert report["summary"]["taint_flow_count"] == len(result.data_flows)
    assert report["summary"]["architecture_dataflow_count"] == 0
    assert report["summary"]["taint_flow_count"] >= 1
    assert "taint_data_flows" in report
    assert len(report["taint_data_flows"]) == len(result.data_flows)
    report_stamped = to_risk_report_json(
        AIBOM(repo_path=tmp_path),
        None,
        dataflow_analysis=result,
        generated_at="2026-10-12 06:40",
        pattern_analysis=SimpleNamespace(findings=[SimpleNamespace(vulnerability_id="PAT-003")]),
        crossfile_taint=SimpleNamespace(
            taint_paths=[],
            confirmed_pattern_ids=[],
            partial_pattern_ids=["PAT-003"],
        ),
    )
    assert report_stamped["generated_at"] == "2026-10-12 06:40"
    assert report_stamped["pattern_analysis"]["not_value_taint"] is True
    assert report_stamped["crossfile_reachability"]["not_value_taint"] is True
    assert report_stamped["dataflows"] == [] or all(
        d.get("kind") == "aibom_architecture" for d in report_stamped.get("dataflows") or []
    )


def test_incomplete_analysis_visible_in_markdown():
    analysis = SimpleNamespace(
        data_flows=[],
        incomplete=True,
        incomplete_reasons=["iteration_cap"],
    )
    md = to_risk_report_markdown(AIBOM(repo_path=Path(".")), None, dataflow_analysis=analysis)
    assert "Analysis incomplete" in md
    assert "iteration_cap" in md
    assert "complete negative" in md.lower() or "truncated" in md.lower()


def test_taint_mermaid_collapses_shared_callee():
    """Two handlers sharing a wrapper produce one sink node, not two graphs."""
    flows = [
        SimpleNamespace(
            sink_category="llm",
            hops=[
                "api.py::chat:1 source user_input",
                "api.py::chat arg -> agent.py::run_agent param user_message",
                "agent.py::run_agent arg -> llm.py::_ollama_chat param messages",
                "llm.py::_ollama_chat:8 sink ollama /api/chat",
            ],
        ),
        SimpleNamespace(
            sink_category="llm",
            hops=[
                "api.py::ask:2 source user_input",
                "api.py::ask arg -> agent.py::run_agent param user_message",
                "agent.py::run_agent arg -> llm.py::_ollama_chat param messages",
                "llm.py::_ollama_chat:8 sink ollama /api/chat",
            ],
        ),
    ]
    mmd = taint_flows_to_mermaid(flows)
    assert "flowchart LR" in mmd
    assert mmd.count("_ollama_chat") >= 1
    assert "run_agent" in mmd
    assert "chat" in mmd and "ask" in mmd
    assert "sourceCls" in mmd and "sinkCls" in mmd


def test_taint_mermaid_empty_without_hops():
    assert taint_flows_to_mermaid([]) == ""
    assert taint_flows_to_mermaid([SimpleNamespace(sink_category="llm", hops=[])]) == ""


def test_architecture_diagram_includes_in_repo_and_ollama(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        "def handler(request):\n"
        "    msg = request.get_json().get('message')\n"
        "    run_agent(msg)\n"
        "def run_agent(user_message):\n"
        "    import requests\n"
        "    requests.post('http://localhost:11434/api/chat', json={'messages': user_message})\n",
        encoding="utf-8",
    )
    result = analyze_dataflows(tmp_path)
    aibom = AIBOM(repo_path=tmp_path)
    from core.models import Component, ComponentType
    aibom.components = [
        Component(id="openai", name="openai", type=ComponentType.LIBRARY),
        Component(id="ollama", name="ollama", type=ComponentType.LIBRARY),
        Component(id="torch", name="torch", type=ComponentType.LIBRARY),
    ]
    diagram = to_ai_component_mermaid(aibom, None, dataflow_analysis=result)
    assert "HTTP / API handlers" in diagram
    assert "In-repo LLM backends" in diagram or "In-repo agents" in diagram
    assert "Ollama /api/chat" in diagram
    assert "PyTorch" in diagram
    html = _dataflow_section(result, [])
    assert "mermaid" in html
    assert "value-taint" in html.lower() or "Value-taint" in html
