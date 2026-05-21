"""Unit tests for crossfile_taint.py — call graph, BFS, severity upgrader."""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from core.crossfile_taint import (
    CrossFileTaintResult,
    FunctionNode,
    TaintPath,
    analyze_crossfile_taint,
    _build_call_graph,
    _build_called_by_index,
    _find_taint_paths,
    _forward_bfs,
    _backward_bfs,
    _upgrade_findings,
    _detect_source,
    _sink_types_for_func,
)
from core.pattern_analyzer import PatternFinding
import ast


def _fn(key, file, name, is_source=False, is_sink=False, source_type=None,
        sink_types=None, calls=None, called_by=None):
    return FunctionNode(
        key=key, file=file, function_name=name, qualified_name=name,
        line_start=1, line_end=20, is_source=is_source, source_type=source_type,
        source_confidence="high", is_sink=is_sink,
        sink_types=sink_types or [], calls=calls or [],
        called_by=called_by or [], parameters=[], is_async=False, decorators=[],
    )


def _make_graph(nodes):
    return {n.key: n for n in nodes}


# ---------------------------------------------------------------------------
# Call graph building
# ---------------------------------------------------------------------------

def test_call_graph_finds_function_nodes():
    with tempfile.TemporaryDirectory() as tmpdir:
        rp = Path(tmpdir)
        (rp / "app.py").write_text("def chat(query):\n    return query\n")
        graph = _build_call_graph(rp)
        assert any("chat" in k for k in graph)


def test_source_detection_fastapi_route():
    src = """
from fastapi import FastAPI
app = FastAPI()

@app.post("/chat")
def chat(query: str):
    return query
"""
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "chat":
            is_src, src_type, _ = _detect_source(node, src)
            assert is_src
            assert src_type in ("fastapi_route", "flask_route", "webhook")
            break


def test_source_detection_flask_route():
    src = """
from flask import Flask
app = Flask(__name__)

@app.route("/api")
def api():
    pass
"""
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "api":
            is_src, src_type, _ = _detect_source(node, src)
            assert is_src
            break


def test_source_detection_websocket_handler():
    src = """
async def ws_handler(websocket):
    data = await websocket.receive_json()
    return data
"""
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            is_src, src_type, _ = _detect_source(node, src)
            if is_src:
                assert src_type == "websocket_handler"
                return
    pytest.fail("No websocket source detected")


def test_source_detection_celery_task():
    src = """
from celery import shared_task

@shared_task
def process_data(data):
    pass
"""
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "process_data":
            is_src, src_type, _ = _detect_source(node, src)
            assert is_src
            assert src_type == "celery_task"
            break


def test_sink_detection_anthropic_call():
    src = """
def call_anthropic():
    client = anthropic.Anthropic()
    result = client.messages.create(model="claude", messages=[])
    return result
"""
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            sink_types = _sink_types_for_func(node)
            assert "llm" in sink_types
            break


def test_sink_detection_openai_call():
    src = """
def call_openai():
    result = openai.chat.completions.create(model="gpt-4", messages=[])
    return result
"""
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            sink_types = _sink_types_for_func(node)
            assert "llm" in sink_types
            break


def test_sink_detection_cursor_execute():
    src = """
def run_query(sql):
    cursor.execute(sql)
"""
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            sink_types = _sink_types_for_func(node)
            assert "sql" in sink_types
            break


# ---------------------------------------------------------------------------
# BFS
# ---------------------------------------------------------------------------

def test_bfs_finds_direct_path_one_hop():
    """source → sink in one hop should be confirmed."""
    source = _fn("app.py::handler", "app.py", "handler", is_source=True, calls=["llm_call"])
    sink = _fn("llm.py::llm_call", "llm.py", "llm_call", is_sink=True, sink_types=["llm"],
               called_by=["app.py::handler"])
    graph = _make_graph([source, sink])
    _build_called_by_index(graph)
    paths = _find_taint_paths(graph, max_hops=6)
    confirmed = [p for p in paths if p.confirmed]
    assert len(confirmed) >= 1
    assert any("app.py::handler" in p.hops for p in confirmed)


def test_bfs_finds_multihop_path_three_hops():
    """source → middle → sink across 3 hops."""
    source = _fn("a.py::handler", "a.py", "handler", is_source=True, calls=["orchestrate"])
    middle = _fn("b.py::orchestrate", "b.py", "orchestrate", calls=["call_llm"],
                 called_by=["a.py::handler"])
    sink = _fn("c.py::call_llm", "c.py", "call_llm", is_sink=True, sink_types=["llm"],
               called_by=["b.py::orchestrate"])
    graph = _make_graph([source, middle, sink])
    _build_called_by_index(graph)
    paths = _find_taint_paths(graph, max_hops=6)
    confirmed = [p for p in paths if p.confirmed]
    assert any(p.hop_count >= 3 for p in confirmed)


def test_bidirectional_bfs_finds_path():
    """Bidirectional BFS should find confirmed path from source to sink."""
    source = _fn("s.py::src", "s.py", "src", is_source=True, source_type="fastapi_route",
                 calls=["mid"])
    middle = _fn("m.py::mid", "m.py", "mid", calls=["snk"],
                 called_by=["s.py::src"])
    sink = _fn("e.py::snk", "e.py", "snk", is_sink=True, sink_types=["llm"],
               called_by=["m.py::mid"])
    graph = _make_graph([source, middle, sink])
    _build_called_by_index(graph)

    forward = _forward_bfs(graph, max_hops=6)
    backward = _backward_bfs(graph, max_hops=6)
    intersection = set(forward.keys()) & set(backward.keys())
    # At least middle or sink should appear in both
    assert bool(intersection)


def test_cycle_detection_prevents_infinite_loop():
    """A cycle should not cause infinite BFS loop."""
    a = _fn("a.py::f", "a.py", "f", is_source=True, calls=["g"])
    b = _fn("b.py::g", "b.py", "g", calls=["f"], called_by=["a.py::f"])  # cycle back
    graph = _make_graph([a, b])
    _build_called_by_index(graph)
    # Should complete without hanging
    paths = _find_taint_paths(graph, max_hops=6)
    assert isinstance(paths, list)


def test_partial_path_recorded_at_three_hops():
    """A 3-hop path that doesn't reach a sink should be recorded as partial."""
    a = _fn("a.py::h", "a.py", "h", is_source=True, calls=["b"])
    b = _fn("b.py::b", "b.py", "b", calls=["c"], called_by=["a.py::h"])
    c = _fn("c.py::c", "c.py", "c", called_by=["b.py::b"])  # not a sink
    graph = _make_graph([a, b, c])
    _build_called_by_index(graph)
    paths = _find_taint_paths(graph, max_hops=6)
    partial = [p for p in paths if p.partial]
    assert len(partial) >= 1
    assert any(p.hop_count >= 3 for p in partial)


def test_severity_upgrader_high_to_critical():
    """A high-severity finding upgraded to critical when taint confirmed."""
    finding = PatternFinding(
        vulnerability_id="PAT-001", title="T", severity="high", confidence="medium",
        category="", owasp_id="", cwe="", file="app.py", line=5, function_name="chat",
        pattern_matched="", evidence=[], framework="",
    )
    tp = TaintPath(
        source_key="app.py::handler", sink_key="llm.py::call",
        sink_type="llm", hops=["app.py::handler", "app.py::chat", "llm.py::call"],
        hop_count=3, confirmed=True, partial=False, vulnerability_type="prompt_injection",
    )
    confirmed_ids: list = []
    partial_ids: list = []
    _upgrade_findings([finding], [tp], confirmed_ids, partial_ids)
    assert finding.severity == "critical"
    assert finding.confirmed_by_taint is True
    assert "PAT-001" in confirmed_ids


def test_fuzzy_function_matching():
    """'rag_chain.run' should fuzzy-match to file 'rag_chain.py' function 'run'."""
    caller = _fn("app.py::chat", "app.py", "chat", is_source=True, calls=["rag_chain.run"])
    callee = _fn("rag_chain.py::run", "rag_chain.py", "run", is_sink=True, sink_types=["llm"])
    graph = _make_graph([caller, callee])
    _build_called_by_index(graph)
    # callee should have caller in its called_by
    assert "app.py::chat" in graph["rag_chain.py::run"].called_by


# ---------------------------------------------------------------------------
# Integration
# ---------------------------------------------------------------------------

def test_analyze_crossfile_taint_returns_result():
    with tempfile.TemporaryDirectory() as tmpdir:
        rp = Path(tmpdir)
        (rp / "app.py").write_text("""
from fastapi import FastAPI
app = FastAPI()

@app.post("/chat")
def chat(query: str):
    return llm.invoke(query)
""")
        result = analyze_crossfile_taint(rp, [])
        assert isinstance(result, CrossFileTaintResult)
        assert result.graph_stats["nodes"] >= 1
