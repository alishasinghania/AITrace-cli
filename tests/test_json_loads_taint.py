"""json.loads provenance: argument taint vs the file_read source label."""
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


def test_request_through_json_loads_to_shell_is_confirmed(tmp_path: Path):
    """Untrusted request data parsed by json.loads must still reach a shell sink."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "import json, subprocess\n"
            "def handle(request):\n"
            "    raw = request.json['payload']\n"
            "    data = json.loads(raw)\n"
            "    subprocess.Popen(f'rm {data}', shell=True)\n"
        ),
    })
    assert any(
        f.sink_category == "rce" and f.source == "user_input"
        for f in flows
    )
    # PAT-025 covers FLOW-RCE at the same shell sink when both apply.
    assert any(
        f.confirmed_by_taint and f.vulnerability_id in {"FLOW-RCE", "PAT-025"}
        for f in findings
    )


def test_json_loads_of_function_param_does_not_confirm_shell(tmp_path: Path):
    """A parameter parsed by json.loads is not attacker-control proof."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "import json, subprocess\n"
            "def run(payload_json):\n"
            "    data = json.loads(payload_json)\n"
            "    subprocess.Popen(f'rm {data}', shell=True)\n"
        ),
    })
    assert not any(f.vulnerability_id == "FLOW-RCE" for f in findings)
    assert all(not f.confirmed_by_taint for f in findings if f.vulnerability_id == "PAT-025")
    rce = [f for f in flows if f.sink_category == "rce"]
    assert all(f.source not in {"user_input", "llm_output", "mcp_tool_arg"} for f in rce)


def test_json_loads_constant_does_not_taint_constant_shell(tmp_path: Path):
    """Parsing a constant JSON value must not taint a later constant command."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "import json, subprocess\n"
            "def run():\n"
            "    _data = json.loads('{\"x\": 1}')\n"
            "    subprocess.Popen('echo ok', shell=True)\n"
        ),
    })
    assert not any(f.sink_category == "rce" for f in flows)
    assert not any(f.vulnerability_id == "FLOW-RCE" for f in findings)


def test_tool_args_through_registry_still_confirmed(tmp_path: Path):
    """Resolved TOOLS dispatch of a tool-arg dict still confirms eval."""
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


def test_resolved_registry_plus_json_loads_param_is_not_confirmed(tmp_path: Path):
    """Target resolution plus json.loads of a parameter does not confirm PAT/FLOW."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "import json, subprocess\n"
            "def purge(payload):\n"
            "    pattern = payload.get('pattern', '*')\n"
            "    subprocess.Popen(f'rm {pattern}', shell=True)\n"
            "HANDLERS = {'cleanup': purge}\n"
            "def dispatch(kind, payload_json):\n"
            "    HANDLERS.get(kind)(json.loads(payload_json or '{}'))\n"
        ),
    })
    assert not any(f.vulnerability_id == "FLOW-RCE" for f in findings)
    assert all(not f.confirmed_by_taint for f in findings if f.vulnerability_id == "PAT-025")
