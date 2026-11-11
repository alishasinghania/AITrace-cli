"""LLM/tool-generated payloads reaching SQL and dynamic-code sinks."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from core.analyzers.crossfile_taint import analyze_crossfile_taint
from core.analyzers.dataflow_analyzer import analyze_dataflows
from core.analyzers.pattern_analyzer import analyze_patterns


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


def test_generate_sql_to_text_execute_is_flow_sql(tmp_path: Path):
    """Explicit SQL generation reaching execute(text(sql)) is dynamic SQL."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "from sqlalchemy import text\n"
            "def run_query(question):\n"
            "    sql = generate_sql(question)\n"
            "    session.execute(text(sql))\n"
        ),
    })
    assert any(f.sink_category == "sql" and f.source == "llm_output" for f in flows)
    assert any(f.vulnerability_id in {"FLOW-SQL", "PAT-003"} for f in findings)


def test_exec_generate_code_is_flow_rce(tmp_path: Path):
    """Explicit code generation reaching exec() is dynamic-code execution."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "def run_analysis(question):\n"
            "    exec(generate_code(question))\n"
        ),
    })
    assert any(f.sink_category == "rce" and f.source == "llm_output" for f in flows)
    assert any(f.vulnerability_id == "FLOW-RCE" for f in findings)


def test_generate_code_through_helper_to_eval_is_flow_rce(tmp_path: Path):
    """Resolved helper must carry the generated payload into eval()."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "def wrap(code):\n"
            "    return code\n"
            "def run(question):\n"
            "    eval(wrap(generate_code(question)))\n"
        ),
    })
    assert any(f.sink_category == "rce" and f.source == "llm_output" for f in flows)
    assert any(f.vulnerability_id == "FLOW-RCE" for f in findings)


def test_cross_file_generate_sql_to_execute_is_flow_sql(tmp_path: Path):
    """Generation in another module still reaches execute(text(sql))."""
    findings, flows = _promote(tmp_path, {
        "gen.py": (
            "def generate_sql(question):\n"
            "    return llm.invoke(question)\n"
        ),
        "db.py": (
            "from sqlalchemy import text\n"
            "from gen import generate_sql\n"
            "def run(question):\n"
            "    sql = generate_sql(question)\n"
            "    session.execute(text(sql))\n"
        ),
    })
    assert any(
        f.sink_category == "sql" and f.file == "db.py" and f.source == "llm_output"
        for f in flows
    )
    assert any(
        f.vulnerability_id in {"FLOW-SQL", "PAT-003"} and f.file == "db.py"
        for f in findings
    )


def test_parameterized_execute_is_not_llm_sql(tmp_path: Path):
    """Bound SQL is not LLM-generated injection even if an LLM is called nearby."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "from sqlalchemy import text\n"
            "def lookup(user_id):\n"
            "    _hint = llm.invoke('unused')\n"
            "    session.execute(text('SELECT * FROM users WHERE id = :id'), {'id': user_id})\n"
        ),
    })
    assert not any(f.sink_category == "sql" for f in flows)
    assert not any(f.vulnerability_id == "FLOW-SQL" for f in findings)
    assert not any(f.vulnerability_id == "PAT-003" for f in findings)


def test_literal_eval_of_literal_is_not_rce(tmp_path: Path):
    """ast.literal_eval on a literal is not dynamic-code execution."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "import ast\n"
            "def parse():\n"
            "    return ast.literal_eval('[1, 2, 3]')\n"
        ),
    })
    assert not any(f.sink_category == "rce" for f in flows)
    assert not any(f.vulnerability_id == "FLOW-RCE" for f in findings)


def test_literal_eval_of_generated_code_is_not_rce(tmp_path: Path):
    """literal_eval remains a non-exec sink even when the argument is generated."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "import ast\n"
            "def parse(question):\n"
            "    return ast.literal_eval(generate_code(question))\n"
        ),
    })
    assert not any(f.sink_category == "rce" for f in flows)
    assert not any(f.vulnerability_id == "FLOW-RCE" for f in findings)


def test_llm_output_does_not_taint_unrelated_values(tmp_path: Path):
    """An unused generation result must not taint a constant SQL string."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "from sqlalchemy import text\n"
            "def run(question):\n"
            "    unused = generate_sql(question)\n"
            "    session.execute(text('SELECT 1'))\n"
        ),
    })
    assert not any(f.sink_category == "sql" for f in flows)
    assert not any(f.vulnerability_id in {"FLOW-SQL", "PAT-003"} for f in findings)


def test_llm_invoke_to_execute_is_not_user_input(tmp_path: Path):
    """Catalogued LLM return used as SQL is generated output, not request taint."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "def handler():\n"
            "    sql = llm.invoke('write a select')\n"
            "    cursor.execute(sql)\n"
        ),
    })
    assert not any(f.sink_category == "sql" and f.source == "user_input" for f in flows)
    assert any(
        f.vulnerability_id in {"FLOW-SQL", "PAT-003"} for f in findings
    )


def test_llm_argument_and_receiver_are_not_llm_output(tmp_path: Path):
    """Only the invoke return is llm_output; the prompt and receiver stay clean."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "def run():\n"
            "    prompt = 'print(1)'\n"
            "    result = llm.invoke(prompt)\n"
            "    exec(prompt)\n"
        ),
    })
    assert not any(f.source == "llm_output" and f.sink_category == "rce" for f in flows)
    assert not any(f.vulnerability_id == "FLOW-RCE" for f in findings)


def test_unused_llm_invoke_does_not_create_rce(tmp_path: Path):
    """An unused catalogued LLM return must not taint a later constant exec()."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "def run():\n"
            "    llm.invoke('write code')\n"
            "    exec('print(1)')\n"
        ),
    })
    assert not any(f.sink_category == "rce" for f in flows)
    assert not any(f.vulnerability_id == "FLOW-RCE" for f in findings)


def test_unrelated_llm_call_then_constant_sql_is_silent(tmp_path: Path):
    """A neighboring llm.invoke does not taint a constant SQL string."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "from sqlalchemy import text\n"
            "def run():\n"
            "    llm.invoke('unused')\n"
            "    session.execute(text('SELECT 1'))\n"
        ),
    })
    assert not any(f.sink_category == "sql" for f in flows)
    assert not any(f.vulnerability_id in {"FLOW-SQL", "PAT-003"} for f in findings)


def test_llm_output_as_bound_parameter_is_not_sql_injection(tmp_path: Path):
    """LLM output used only as a bound value is not interpolated SQL."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "from sqlalchemy import text\n"
            "def lookup():\n"
            "    generated = llm.invoke('an id')\n"
            "    session.execute(\n"
            "        text('SELECT * FROM users WHERE id = :id'),\n"
            "        {'id': generated},\n"
            "    )\n"
        ),
    })
    assert not any(f.sink_category == "sql" for f in flows)
    assert not any(f.vulnerability_id == "FLOW-SQL" for f in findings)
    assert not any(f.vulnerability_id == "PAT-003" for f in findings)


def test_assigned_generate_code_reaches_exec(tmp_path: Path):
    """Assignment aliasing still carries llm_output into exec()."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "def run(question):\n"
            "    code = generate_code(question)\n"
            "    payload = code\n"
            "    exec(payload)\n"
        ),
    })
    assert any(f.sink_category == "rce" and f.source == "llm_output" for f in flows)
    assert any(f.vulnerability_id == "FLOW-RCE" for f in findings)
