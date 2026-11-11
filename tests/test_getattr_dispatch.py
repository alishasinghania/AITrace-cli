"""getattr(registry, name) dispatch: resolve only statically known registries."""
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


def test_getattr_tools_starred_args_reach_eval(tmp_path: Path):
    """getattr(TOOLS, name)(**arguments) reaches eval on a resolvable target."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "def calc(input):\n"
            "    eval(input)\n"
            "TOOLS = {'calc': calc}\n"
            "def handle(reply):\n"
            "    for call in reply.get('tool_calls', []) or []:\n"
            "        getattr(TOOLS, call['name'])(**call.get('arguments', {}))\n"
        ),
    })
    assert any(f.sink_category == "rce" and f.source == "llm_output" for f in flows)
    assert any(f.vulnerability_id == "FLOW-RCE" and f.confirmed_by_taint for f in findings)


def test_getattr_assigned_then_exec(tmp_path: Path):
    """fn = getattr(TOOLS, name); fn(**arguments) still reaches exec."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "def run(code):\n"
            "    exec(code)\n"
            "TOOLS = {'run': run}\n"
            "def handle(reply):\n"
            "    for call in reply.get('tool_calls', []) or []:\n"
            "        fn = getattr(TOOLS, call['name'])\n"
            "        fn(**call.get('arguments', {}))\n"
        ),
    })
    assert any(f.sink_category == "rce" and f.source == "llm_output" for f in flows)
    assert any(f.vulnerability_id == "FLOW-RCE" and f.confirmed_by_taint for f in findings)


def test_getattr_through_helper_reaches_eval(tmp_path: Path):
    """A helper that expands **arguments through getattr still reports."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "def calc(input):\n"
            "    eval(input)\n"
            "TOOLS = {'calc': calc}\n"
            "def invoke(name, arguments):\n"
            "    return getattr(TOOLS, name)(**arguments)\n"
            "def handle(reply):\n"
            "    for call in reply.get('tool_calls', []) or []:\n"
            "        invoke(call['name'], call.get('arguments', {}))\n"
        ),
    })
    assert any(f.sink_category == "rce" and f.source == "llm_output" for f in flows)
    assert any(f.vulnerability_id == "FLOW-RCE" and f.confirmed_by_taint for f in findings)


def test_cross_file_getattr_tools_reach_eval(tmp_path: Path):
    """Imported TOOLS through getattr still reaches a cross-file eval sink."""
    findings, flows = _promote(tmp_path, {
        "tools.py": (
            "def calc(input):\n"
            "    eval(input)\n"
            "TOOLS = {'calc': calc}\n"
        ),
        "agent.py": (
            "from tools import TOOLS\n"
            "def handle(reply):\n"
            "    for call in reply.get('tool_calls', []) or []:\n"
            "        getattr(TOOLS, call['name'])(**call.get('arguments', {}))\n"
        ),
    })
    assert any(
        f.sink_category == "rce" and f.file == "tools.py" and f.source == "llm_output"
        for f in flows
    )
    assert any(f.vulnerability_id == "FLOW-RCE" and f.file == "tools.py" for f in findings)


def test_explicit_registry_dispatch_still_works(tmp_path: Path):
    """TOOLS.get(name)(**arguments) remains confirmed after getattr support."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "def calc(input):\n"
            "    eval(input)\n"
            "TOOLS = {'calc': calc}\n"
            "def handle(reply):\n"
            "    for call in reply.get('tool_calls', []) or []:\n"
            "        TOOLS.get(call['name'])(**call.get('arguments', {}))\n"
        ),
    })
    assert any(f.sink_category == "rce" and f.source == "llm_output" for f in flows)
    assert any(f.vulnerability_id == "FLOW-RCE" and f.confirmed_by_taint for f in findings)


def test_getattr_unknown_object_is_not_confirmed(tmp_path: Path):
    """getattr on an unknown object must not invent a sink flow."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "def handle(reply):\n"
            "    for call in reply.get('tool_calls', []) or []:\n"
            "        getattr(reply, call['name'])(**call.get('arguments', {}))\n"
        ),
    })
    assert not any(f.sink_category == "rce" for f in flows)
    assert not any(f.vulnerability_id == "FLOW-RCE" for f in findings)


def test_getattr_literal_name_does_not_bind_unrelated_function(tmp_path: Path):
    """A matching function name is not a target unless the object is a registry."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "def calc(input):\n"
            "    eval(input)\n"
            "def handle(reply):\n"
            "    for call in reply.get('tool_calls', []) or []:\n"
            "        obj = object()\n"
            "        fn = getattr(obj, 'calc', None)\n"
            "        fn(**call.get('arguments', {}))\n"
        ),
    })
    assert not any(f.sink_category == "rce" for f in flows)
    assert not any(f.vulnerability_id == "FLOW-RCE" for f in findings)


def test_getattr_unresolved_attribute_is_not_confirmed(tmp_path: Path):
    """Arbitrary getattr(obj, attr) does not create a confirmed flow."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "def calc(input):\n"
            "    eval(input)\n"
            "def handle(obj, attr, arguments):\n"
            "    getattr(obj, attr)(**arguments)\n"
        ),
    })
    assert not any(f.sink_category == "rce" for f in flows)
    assert not any(f.vulnerability_id == "FLOW-RCE" for f in findings)


def test_getattr_weak_origin_does_not_confirm_shell(tmp_path: Path):
    """Resolving getattr(HANDLERS, kind) does not confirm a function_param."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "import subprocess\n"
            "def purge(pattern):\n"
            "    subprocess.Popen(f'rm {pattern}', shell=True)\n"
            "HANDLERS = {'cleanup': purge}\n"
            "def dispatch(kind, pattern):\n"
            "    getattr(HANDLERS, kind)(pattern)\n"
        ),
    })
    assert not any(f.vulnerability_id == "FLOW-RCE" for f in findings)
    assert all(not f.confirmed_by_taint for f in findings if f.vulnerability_id == "PAT-025")
    rce = [f for f in flows if f.sink_category == "rce"]
    assert all(f.source not in {"user_input", "llm_output", "mcp_tool_arg"} for f in rce)


def test_getattr_constant_kwargs_does_not_taint_eval(tmp_path: Path):
    """A neighboring tool-call dict must not taint a constant **kwargs expansion."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "def calc(input):\n"
            "    eval(input)\n"
            "TOOLS = {'calc': calc}\n"
            "def handle(reply):\n"
            "    for call in reply.get('tool_calls', []) or []:\n"
            "        _unused = call.get('arguments', {})\n"
            "        getattr(TOOLS, call['name'])(**{'input': '1+1'})\n"
        ),
    })
    assert not any(f.sink_category == "rce" for f in flows)
    assert not any(f.vulnerability_id == "FLOW-RCE" for f in findings)


def test_getattr_bound_sql_params_are_not_injection(tmp_path: Path):
    """**tool arguments used only as bound SQL values are not interpolated SQL."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "from sqlalchemy import text\n"
            "def run_sql(value):\n"
            "    session.execute(text('SELECT * FROM t WHERE id = :id'), {'id': value})\n"
            "TOOLS = {'run_sql': run_sql}\n"
            "def handle(reply):\n"
            "    for call in reply.get('tool_calls', []) or []:\n"
            "        getattr(TOOLS, call['name'])(**call.get('arguments', {}))\n"
        ),
    })
    assert not any(f.sink_category == "sql" for f in flows)
    assert not any(f.vulnerability_id == "FLOW-SQL" for f in findings)
    assert not any(f.vulnerability_id == "PAT-003" for f in findings)


def test_getattr_resolution_without_args_does_not_taint(tmp_path: Path):
    """Resolving getattr(TOOLS, name)() does not taint callee parameters."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "def calc(input):\n"
            "    eval(input)\n"
            "TOOLS = {'calc': calc}\n"
            "def dispatch(name):\n"
            "    getattr(TOOLS, name)()\n"
        ),
    })
    assert not any(f.sink_category == "rce" for f in flows)
    assert not any(f.vulnerability_id == "FLOW-RCE" for f in findings)
