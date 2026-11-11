"""Model tool-call arguments reaching eval, exec, and SQL sinks."""
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


def test_tool_call_argument_to_eval_is_flow_rce(tmp_path: Path):
    """Explicit tool-call argument reaching eval() is value taint."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "def handle(message):\n"
            "    expr = message.tool_calls[0].arguments['expr']\n"
            "    eval(expr)\n"
        ),
    })
    assert any(f.sink_category == "rce" and f.source == "llm_output" for f in flows)
    assert any(f.vulnerability_id == "FLOW-RCE" for f in findings)


def test_tool_call_argument_assigned_then_exec(tmp_path: Path):
    """Assignment aliasing still carries the tool-call payload into exec()."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "def handle(message):\n"
            "    args = message.tool_calls[0].arguments\n"
            "    code = args['code']\n"
            "    exec(code)\n"
        ),
    })
    assert any(f.sink_category == "rce" and f.source == "llm_output" for f in flows)
    assert any(f.vulnerability_id == "FLOW-RCE" for f in findings)


def test_tool_call_argument_through_helper_to_eval(tmp_path: Path):
    """Resolved helper must propagate a tool-call argument into eval()."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "def wrap(expr):\n"
            "    return expr\n"
            "def handle(message):\n"
            "    eval(wrap(message.tool_calls[0].arguments['expr']))\n"
        ),
    })
    assert any(f.sink_category == "rce" and f.source == "llm_output" for f in flows)
    assert any(f.vulnerability_id == "FLOW-RCE" for f in findings)


def test_cross_file_tool_arg_to_eval(tmp_path: Path):
    """Named-argument cross-file call still carries the tool-call payload."""
    findings, flows = _promote(tmp_path, {
        "tools.py": (
            "def run_expr(expr):\n"
            "    eval(expr)\n"
        ),
        "agent.py": (
            "from tools import run_expr\n"
            "def handle(message):\n"
            "    run_expr(message.tool_calls[0].arguments['expr'])\n"
        ),
    })
    assert any(
        f.sink_category == "rce" and f.file == "tools.py" and f.source == "llm_output"
        for f in flows
    )
    assert any(f.vulnerability_id == "FLOW-RCE" and f.file == "tools.py" for f in findings)


def test_loop_tool_calls_get_arguments_to_eval(tmp_path: Path):
    """for call in reply['tool_calls']: call.get('arguments') is identifiable."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "def handle(reply):\n"
            "    for call in reply.get('tool_calls', []) or []:\n"
            "        args = call.get('arguments', {})\n"
            "        eval(args.get('expr'))\n"
        ),
    })
    assert any(f.sink_category == "rce" and f.source == "llm_output" for f in flows)
    assert any(f.vulnerability_id == "FLOW-RCE" for f in findings)


def test_tool_arg_to_execute_text_is_flow_sql(tmp_path: Path):
    """Tool-call SQL string reaching execute(text(sql)) is dynamic SQL."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "from sqlalchemy import text\n"
            "def handle(message):\n"
            "    sql = message.tool_calls[0].arguments['query']\n"
            "    session.execute(text(sql))\n"
        ),
    })
    assert any(f.sink_category == "sql" and f.source == "llm_output" for f in flows)
    assert any(f.vulnerability_id in {"FLOW-SQL", "PAT-003"} for f in findings)


def test_unused_tool_argument_does_not_taint_constant_exec(tmp_path: Path):
    """An unused tool-call argument must not taint a later constant exec()."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "def handle(message):\n"
            "    unused = message.tool_calls[0].arguments['expr']\n"
            "    exec('print(1)')\n"
        ),
    })
    assert not any(f.sink_category == "rce" for f in flows)
    assert not any(f.vulnerability_id == "FLOW-RCE" for f in findings)


def test_unrelated_tool_call_does_not_taint_constant_sql(tmp_path: Path):
    """A neighboring tool-call payload does not taint a constant SQL string."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "from sqlalchemy import text\n"
            "def handle(message):\n"
            "    _args = message.tool_calls[0].arguments\n"
            "    session.execute(text('SELECT 1'))\n"
        ),
    })
    assert not any(f.sink_category == "sql" for f in flows)
    assert not any(f.vulnerability_id in {"FLOW-SQL", "PAT-003"} for f in findings)


def test_tool_arg_as_bound_parameter_is_not_sql_injection(tmp_path: Path):
    """Tool-call value used only as a bound parameter is not interpolated SQL."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "from sqlalchemy import text\n"
            "def handle(message):\n"
            "    value = message.tool_calls[0].arguments['id']\n"
            "    session.execute(text('SELECT * FROM t WHERE id = :id'), {'id': value})\n"
        ),
    })
    assert not any(f.sink_category == "sql" for f in flows)
    assert not any(f.vulnerability_id == "FLOW-SQL" for f in findings)
    assert not any(f.vulnerability_id == "PAT-003" for f in findings)


def test_ordinary_function_parameter_is_not_tool_arg_rce(tmp_path: Path):
    """Ordinary parameters are not reclassified as model tool arguments."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "def calc(input):\n"
            "    eval(input)\n"
        ),
    })
    assert not any(f.sink_category == "rce" for f in flows)
    assert not any(f.vulnerability_id == "FLOW-RCE" for f in findings)


def test_fn_starred_tool_args_reach_eval(tmp_path: Path):
    """Resolved fn(**tool_arguments) still carries the payload into eval()."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "def calc(input):\n"
            "    eval(input)\n"
            "def handle(reply):\n"
            "    for call in reply.get('tool_calls', []) or []:\n"
            "        fn = calc\n"
            "        arguments = call.get('arguments', {})\n"
            "        fn(**arguments)\n"
        ),
    })
    assert any(
        f.sink_category == "rce" and f.source == "llm_output" and f.file == "app.py"
        for f in flows
    )
    assert any(f.vulnerability_id == "FLOW-RCE" for f in findings)


def test_tools_get_starred_args_reach_eval(tmp_path: Path):
    """TOOLS.get(name)(**arguments) reaches eval when the registry is resolvable."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "def calc(input):\n"
            "    eval(input)\n"
            "TOOLS = {'calc': calc}\n"
            "def handle(reply):\n"
            "    for call in reply.get('tool_calls', []) or []:\n"
            "        fn = TOOLS.get(call['name'])\n"
            "        fn(**call.get('arguments', {}))\n"
        ),
    })
    assert any(f.sink_category == "rce" and f.source == "llm_output" for f in flows)
    assert any(f.vulnerability_id == "FLOW-RCE" for f in findings)


def test_tools_subscript_starred_args_reach_sql(tmp_path: Path):
    """TOOLS[name](**arguments) reaches execute(text(...)) for resolvable targets."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "from sqlalchemy import text\n"
            "def run_sql(input):\n"
            "    session.execute(text(input))\n"
            "TOOLS = {'run_sql': run_sql}\n"
            "def handle(reply):\n"
            "    for call in reply.get('tool_calls', []) or []:\n"
            "        TOOLS[call['name']](**call.get('arguments', {}))\n"
        ),
    })
    assert any(f.sink_category == "sql" and f.source == "llm_output" for f in flows)
    assert any(f.vulnerability_id in {"FLOW-SQL", "PAT-003"} for f in findings)


def test_helper_starred_tool_args_reach_eval(tmp_path: Path):
    """A helper that expands **arguments into a named tool still reports."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "def calc(input):\n"
            "    eval(input)\n"
            "def invoke(arguments):\n"
            "    return calc(**arguments)\n"
            "def handle(reply):\n"
            "    for call in reply.get('tool_calls', []) or []:\n"
            "        invoke(call.get('arguments', {}))\n"
        ),
    })
    assert any(f.sink_category == "rce" and f.source == "llm_output" for f in flows)
    assert any(f.vulnerability_id == "FLOW-RCE" for f in findings)


def test_cross_file_tools_dict_starred_args_reach_eval(tmp_path: Path):
    """Imported TOOLS[name](**arguments) still reaches a cross-file eval sink."""
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
            "        TOOLS[call['name']](**call.get('arguments', {}))\n"
        ),
    })
    assert any(
        f.sink_category == "rce" and f.file == "tools.py" and f.source == "llm_output"
        for f in flows
    )
    assert any(f.vulnerability_id == "FLOW-RCE" and f.file == "tools.py" for f in findings)


def test_constant_kwargs_dict_does_not_taint_eval(tmp_path: Path):
    """A neighboring tool-call dict must not taint a constant **kwargs expansion."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "def calc(input):\n"
            "    eval(input)\n"
            "def handle(reply):\n"
            "    for call in reply.get('tool_calls', []) or []:\n"
            "        _unused = call.get('arguments', {})\n"
            "        calc(**{'input': '1+1'})\n"
        ),
    })
    assert not any(f.sink_category == "rce" for f in flows)
    assert not any(f.vulnerability_id == "FLOW-RCE" for f in findings)


def test_unresolved_registry_starred_args_are_not_confirmed(tmp_path: Path):
    """An unresolved dynamic target must not invent a sink flow."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "def handle(reply):\n"
            "    for call in reply.get('tool_calls', []) or []:\n"
            "        registry[call['name']](**call.get('arguments', {}))\n"
        ),
    })
    assert not any(f.sink_category == "rce" for f in flows)
    assert not any(f.vulnerability_id == "FLOW-RCE" for f in findings)


def test_registry_does_not_taint_unrelated_eval(tmp_path: Path):
    """A function that is not a resolvable TOOLS target stays untainted."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "def other(input):\n"
            "    eval(input)\n"
            "def calc(input):\n"
            "    return input\n"
            "TOOLS = {'calc': calc}\n"
            "def handle(reply):\n"
            "    for call in reply.get('tool_calls', []) or []:\n"
            "        TOOLS[call['name']](**call.get('arguments', {}))\n"
        ),
    })
    assert not any(f.sink_category == "rce" for f in flows)
    assert not any(f.vulnerability_id == "FLOW-RCE" for f in findings)


def test_explicit_constant_binding_not_overridden_by_kwargs(tmp_path: Path):
    """An explicit constant argument is not replaced by a later **tool dict."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "def calc(input):\n"
            "    eval(input)\n"
            "def handle(reply):\n"
            "    for call in reply.get('tool_calls', []) or []:\n"
            "        extra = call.get('arguments', {})\n"
            "        calc(input='1+1', **extra)\n"
        ),
    })
    assert not any(f.sink_category == "rce" for f in flows)
    assert not any(f.vulnerability_id == "FLOW-RCE" for f in findings)


def test_starred_tool_args_as_bound_sql_params_are_not_injection(tmp_path: Path):
    """**tool arguments used only as bound SQL values are not interpolated SQL."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "from sqlalchemy import text\n"
            "def run_sql(value):\n"
            "    session.execute(text('SELECT * FROM t WHERE id = :id'), {'id': value})\n"
            "def handle(reply):\n"
            "    for call in reply.get('tool_calls', []) or []:\n"
            "        fn = run_sql\n"
            "        fn(**call.get('arguments', {}))\n"
        ),
    })
    assert not any(f.sink_category == "sql" for f in flows)
    assert not any(f.vulnerability_id == "FLOW-SQL" for f in findings)
    assert not any(f.vulnerability_id == "PAT-003" for f in findings)


def test_tool_dispatch_keeps_calc_and_run_sql_findings(tmp_path: Path):
    """Explicit tool-arg dicts still confirm calc eval and run_sql execute."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "from sqlalchemy import text\n"
            "def calc(input):\n"
            "    eval(input)\n"
            "def run_sql(input):\n"
            "    session.execute(text(input))\n"
            "TOOLS = {'calc': calc, 'run_sql': run_sql}\n"
            "def handle(reply):\n"
            "    for call in reply.get('tool_calls', []) or []:\n"
            "        TOOLS.get(call['name'])(**call.get('arguments', {}))\n"
        ),
    })
    assert any(
        f.sink_category == "rce" and f.source == "llm_output" and f.sink_function == "calc"
        for f in flows
    )
    assert any(
        f.sink_category == "sql" and f.source == "llm_output" and f.sink_function == "run_sql"
        for f in flows
    )
    assert any(f.vulnerability_id == "FLOW-RCE" and f.confirmed_by_taint for f in findings)
    assert any(f.vulnerability_id in {"FLOW-SQL", "PAT-003"} for f in findings)


def test_registry_json_loads_does_not_confirm_shell(tmp_path: Path):
    """Resolving HANDLERS.get(kind) must not confirm file_read as attacker taint."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "import json, subprocess\n"
            "def purge(payload):\n"
            "    pattern = payload.get('pattern', '*')\n"
            "    subprocess.Popen(f'rm {pattern}', shell=True)\n"
            "HANDLERS = {'cleanup': purge}\n"
            "def dispatch(kind, payload_json):\n"
            "    handler = HANDLERS.get(kind)\n"
            "    handler(json.loads(payload_json or '{}'))\n"
        ),
    })
    pat = [f for f in findings if f.vulnerability_id == "PAT-025"]
    assert all(not f.confirmed_by_taint for f in pat)
    assert not any(f.vulnerability_id == "FLOW-RCE" for f in findings)
    rce = [f for f in flows if f.sink_category == "rce"]
    assert all(getattr(f, "taint_kind", "") != "payload" or f.confidence == "may" for f in rce)
    assert all(f.source not in {"user_input", "llm_output", "mcp_tool_arg"} for f in rce)


def test_file_read_label_is_not_confirmed_rce(tmp_path: Path):
    """open().read() reaching eval is file_read, not confirmed attacker RCE."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "def load(path):\n"
            "    data = open(path).read()\n"
            "    eval(data)\n"
        ),
    })
    assert not any(f.vulnerability_id == "FLOW-RCE" for f in findings)
    rce = [f for f in flows if f.sink_category == "rce"]
    assert all(f.source != "user_input" for f in rce)
    assert all(getattr(f, "taint_kind", "") != "payload" or f.confidence == "may" for f in rce)


def test_resolved_registry_without_args_does_not_taint_params(tmp_path: Path):
    """Resolving a registry target does not taint its parameters by itself."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "def calc(input):\n"
            "    eval(input)\n"
            "HANDLERS = {'calc': calc}\n"
            "def dispatch(kind):\n"
            "    HANDLERS.get(kind)()\n"
        ),
    })
    assert not any(f.sink_category == "rce" for f in flows)
    assert not any(f.vulnerability_id == "FLOW-RCE" for f in findings)
