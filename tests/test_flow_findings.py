"""FLOW-* promotion, SQL parameterization, and finding-identity tests."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from core.analyzers.dataflow_analyzer import analyze_dataflows
from core.analyzers.crossfile_taint import analyze_crossfile_taint
from core.analyzers.pattern_analyzer import analyze_patterns
from core.analyzers.taint_catalog import classify_sink
import ast


def _write(tmp: Path, files: dict) -> Path:
    for name, src in files.items():
        p = tmp / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(src, encoding="utf-8")
    return tmp


def _promote(tmp: Path, files: dict):
    root = _write(tmp, files)
    flows = analyze_dataflows(root)
    patterns = analyze_patterns(root)
    analyze_crossfile_taint(root, patterns.findings, data_flows=flows.data_flows)
    return patterns.findings, flows.data_flows


def _ids(findings) -> set:
    return {f.vulnerability_id for f in findings}


# ---------------------------------------------------------------------------
# Shared sink taxonomy
# ---------------------------------------------------------------------------

def test_cursor_execute_is_sql_sink():
    node = ast.parse("cursor.execute(q)").body[0].value
    assert "sql" in classify_sink(node)


def test_widget_execute_is_not_sql_sink():
    node = ast.parse("widget.execute(q)").body[0].value
    assert "sql" not in classify_sink(node)


def test_router_invoke_is_not_llm_sink():
    node = ast.parse("router.invoke(payload)").body[0].value
    assert "llm" not in classify_sink(node)


def test_llm_invoke_is_llm_sink():
    node = ast.parse("llm.invoke(payload)").body[0].value
    assert "llm" in classify_sink(node)


# ---------------------------------------------------------------------------
# FLOW-LLM promotion
# ---------------------------------------------------------------------------

def test_direct_request_to_llm_promotes_flow_llm(tmp_path: Path):
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "def handler(request):\n"
            "    message = request.json['message']\n"
            "    llm.invoke(message)\n"
        ),
    })
    assert any(f.sink_category == "llm" and f.source == "user_input" for f in flows)
    llm_findings = [f for f in findings if f.vulnerability_id == "FLOW-LLM"]
    assert llm_findings
    assert llm_findings[0].confirmed_by_taint is True
    assert llm_findings[0].severity != "critical"
    assert getattr(llm_findings[0], "taint_kind", "payload") == "payload"


def test_fstring_request_to_llm_promotes_flow_llm(tmp_path: Path):
    findings, _ = _promote(tmp_path, {
        "app.py": (
            "def handler(request):\n"
            "    message = request.json['message']\n"
            "    llm.invoke(f'q={message}')\n"
        ),
    })
    assert any(f.vulnerability_id == "FLOW-LLM" for f in findings)


def test_cross_file_wrapper_still_promotes_flow_llm(tmp_path: Path):
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "from service import ask\n"
            "def handler(request):\n"
            "    return ask(request.json['message'])\n"
        ),
        "service.py": (
            "def ask(prompt):\n"
            "    return llm.invoke(prompt)\n"
        ),
    })
    assert any(f.sink_category == "llm" and f.source_file == "app.py" for f in flows)
    assert any(f.vulnerability_id == "FLOW-LLM" and f.file == "service.py" for f in findings)


def test_unresolved_wrapper_does_not_promote_flow_llm(tmp_path: Path):
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "from vendor import transform\n"
            "def handler(request):\n"
            "    msg = request.json['message']\n"
            "    x = transform(msg)\n"
            "    llm.invoke(x)\n"
        ),
    })
    assert not any(f.sink_category == "llm" and f.source == "user_input" for f in flows)
    assert not any(f.vulnerability_id == "FLOW-LLM" for f in findings)


def test_constant_prompt_does_not_promote_flow_llm(tmp_path: Path):
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "def handler(request):\n"
            "    llm.invoke('static prompt')\n"
        ),
    })
    assert not any(f.sink_category == "llm" for f in flows)
    assert not any(f.vulnerability_id == "FLOW-LLM" for f in findings)


def test_two_llm_sinks_are_separate_findings(tmp_path: Path):
    findings, _ = _promote(tmp_path, {
        "app.py": (
            "def handler(request):\n"
            "    msg = request.json['message']\n"
            "    llm.invoke(msg)\n"
            "    llm.ainvoke(msg)\n"
        ),
    })
    llm_findings = [f for f in findings if f.vulnerability_id == "FLOW-LLM"]
    lines = {f.line for f in llm_findings}
    assert len(lines) >= 2


def test_llm_without_user_input_is_not_confirmed_taint(tmp_path: Path):
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "def handler():\n"
            "    llm.invoke(config.prompt)\n"
        ),
    })
    assert not any(f.source == "user_input" for f in flows)
    assert not any(f.vulnerability_id == "FLOW-LLM" for f in findings)


def test_lookup_id_does_not_promote_payload_flow_llm(tmp_path: Path):
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "def handler(request):\n"
            "    record_id = request.json['id']\n"
            "    obj = repository.load(record_id)\n"
            "    llm.invoke(f'Brief {obj.title}')\n"
        ),
    })
    assert not any(f.sink_category == "llm" and f.source == "user_input" for f in flows)
    assert not any(f.vulnerability_id == "FLOW-LLM" for f in findings)


# ---------------------------------------------------------------------------
# SQL parameterization vs interpolation
# ---------------------------------------------------------------------------

def test_parameterized_sql_is_not_flow_sql(tmp_path: Path):
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "def handler(request):\n"
            "    record_id = request.json['id']\n"
            "    cursor.execute('SELECT * FROM records WHERE id = ?', (record_id,))\n"
        ),
    })
    assert not any(f.sink_category == "sql" for f in flows)
    assert "FLOW-SQL" not in _ids(findings)


def test_fstring_sql_assigned_then_executed_is_flow_sql(tmp_path: Path):
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "def handler(request):\n"
            "    record_id = request.json['id']\n"
            "    query = f\"SELECT * FROM records WHERE id = {record_id}\"\n"
            "    cursor.execute(query)\n"
        ),
    })
    assert any(f.sink_category == "sql" and f.source == "user_input" for f in flows)
    assert any(f.vulnerability_id in {"FLOW-SQL", "PAT-003"} for f in findings)


def test_concat_sql_assigned_then_executed_is_flow_sql(tmp_path: Path):
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "def handler(request):\n"
            "    record_id = request.json['id']\n"
            "    query = 'SELECT * FROM records WHERE id = ' + record_id\n"
            "    cursor.execute(query)\n"
        ),
    })
    assert any(f.sink_category == "sql" and f.source == "user_input" for f in flows)
    assert any(f.vulnerability_id in {"FLOW-SQL", "PAT-003"} for f in findings)


def test_cross_file_sql_construction_is_flow_sql(tmp_path: Path):
    findings, flows = _promote(tmp_path, {
        "build.py": (
            "def make_query(request):\n"
            "    record_id = request.json['id']\n"
            "    return f'SELECT * FROM records WHERE id = {record_id}'\n"
        ),
        "db.py": (
            "from build import make_query\n"
            "def run(request):\n"
            "    cursor.execute(make_query(request))\n"
        ),
    })
    assert any(f.sink_category == "sql" and f.file == "db.py" for f in flows)
    assert any(f.vulnerability_id == "FLOW-SQL" and f.file == "db.py" for f in findings)


def test_llm_generated_sql_is_not_labeled_as_request_injection(tmp_path: Path):
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "def handler():\n"
            "    sql = llm.invoke('write a select')\n"
            "    cursor.execute(sql)\n"
        ),
    })
    assert not any(f.sink_category == "sql" and f.source == "user_input" for f in flows)
    pat = [f for f in findings if f.vulnerability_id == "PAT-003"]
    assert pat
    assert "LLM" in pat[0].title or "llm" in pat[0].pattern_matched.lower()
    assert "FLOW-SQL" not in _ids(findings) or all(
        f.source != "user_input" for f in flows if f.sink_category == "sql"
    )


# ---------------------------------------------------------------------------
# Deduplication / identity
# ---------------------------------------------------------------------------

def test_same_sql_sink_does_not_emit_duplicate_flow_and_pattern(tmp_path: Path):
    findings, _ = _promote(tmp_path, {
        "app.py": (
            "def handler(request):\n"
            "    record_id = request.json['id']\n"
            "    query = f\"SELECT * FROM t WHERE id = {record_id}\"\n"
            "    cursor.execute(query)\n"
        ),
    })
    sql_at = [
        (f.vulnerability_id, f.line)
        for f in findings
        if f.vulnerability_id in {"PAT-003", "FLOW-SQL"}
    ]
    lines = {}
    for vid, line in sql_at:
        lines.setdefault(line, set()).add(vid)
    for vids in lines.values():
        assert not ({"PAT-003", "FLOW-SQL"} <= vids)


def test_two_sql_sinks_in_one_file_are_both_represented(tmp_path: Path):
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "def handler(request):\n"
            "    a = request.json['a']\n"
            "    b = request.json['b']\n"
            "    cursor.execute(f'SELECT {a}')\n"
            "    cursor.execute(f'SELECT {b}')\n"
        ),
    })
    sql_flows = [f for f in flows if f.sink_category == "sql"]
    assert len({f.line for f in sql_flows}) >= 2
    sql_findings = [f for f in findings if f.vulnerability_id in {"PAT-003", "FLOW-SQL"}]
    assert len({f.line for f in sql_findings}) >= 2


def test_same_source_two_sink_categories(tmp_path: Path):
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "import os\n"
            "def handler(request):\n"
            "    x = request.json['x']\n"
            "    llm.invoke(x)\n"
            "    os.system(x)\n"
        ),
    })
    cats = {f.sink_category for f in flows}
    assert "llm" in cats and "rce" in cats
    ids = _ids(findings)
    assert "FLOW-LLM" in ids
    assert "FLOW-RCE" in ids or "PAT-025" in ids


def test_sql_pattern_does_not_suppress_llm_flow_elsewhere(tmp_path: Path):
    findings, _ = _promote(tmp_path, {
        "app.py": (
            "def handler(request):\n"
            "    record_id = request.json['id']\n"
            "    msg = request.json['message']\n"
            "    cursor.execute(f'SELECT {record_id}')\n"
            "    llm.invoke(msg)\n"
        ),
    })
    ids = _ids(findings)
    assert any(v in ids for v in ("PAT-003", "FLOW-SQL"))
    assert "FLOW-LLM" in ids
