"""Integration tests for genuine interprocedural / cross-file value taint."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from core.analyzers.dataflow_analyzer import analyze_dataflows


def _result(tmp: Path, files, **kwargs):
    for name, src in files.items():
        p = tmp / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(src, encoding="utf-8")
    return analyze_dataflows(tmp, **kwargs)


def _flows(tmp: Path, files, **kwargs):
    return _result(tmp, files, **kwargs).data_flows


def test_same_function_source_to_llm(tmp_path: Path):
    flows = _flows(tmp_path, {
        "app.py": (
            "def handler(request):\n"
            "    value = request.json['message']\n"
            "    return llm.invoke(value)\n"
        ),
    })
    assert len(flows) == 1
    f = flows[0]
    assert f.source == "user_input"
    assert f.sink_category == "llm"
    assert f.file == "app.py"
    assert f.source_file == "app.py"
    assert f.sink_function == "handler"


def test_same_file_argument_propagation(tmp_path: Path):
    flows = _flows(tmp_path, {
        "app.py": (
            "def handler(request):\n"
            "    return first(request.json['message'])\n"
            "def first(value):\n"
            "    return second(value)\n"
            "def second(prompt):\n"
            "    return llm.invoke(prompt)\n"
        ),
    })
    assert any(f.sink_function == "second" and f.source == "user_input" for f in flows)
    hops = " ".join(flows[0].hops)
    assert "second" in hops or any("param prompt" in h for f in flows for h in f.hops)


def test_cross_file_argument_to_parameter(tmp_path: Path):
    flows = _flows(tmp_path, {
        "app.py": (
            "from service import process\n"
            "def handler(request):\n"
            "    value = request.json['message']\n"
            "    return process(value)\n"
        ),
        "service.py": (
            "def process(text):\n"
            "    return llm.invoke(text)\n"
        ),
    })
    assert len(flows) >= 1
    f = flows[0]
    assert f.source_file == "app.py"
    assert f.file == "service.py"
    assert f.sink_function == "process"
    assert any("service.py::process" in h for h in f.hops)


def test_three_file_chain(tmp_path: Path):
    flows = _flows(tmp_path, {
        "a.py": (
            "from b import first\n"
            "def handler(request):\n"
            "    return first(request.json['message'])\n"
        ),
        "b.py": (
            "from c import second\n"
            "def first(value):\n"
            "    return second(value)\n"
        ),
        "c.py": (
            "def second(prompt):\n"
            "    return llm.invoke(prompt)\n"
        ),
    })
    f = next(x for x in flows if x.file == "c.py")
    assert f.source_file == "a.py"
    assert f.sink_function == "second"
    assert len(f.hops) >= 3


def test_return_value_propagation(tmp_path: Path):
    flows = _flows(tmp_path, {
        "app.py": (
            "def load_input(request):\n"
            "    return request.json['message']\n"
            "def handler(request):\n"
            "    prompt = load_input(request)\n"
            "    return llm.invoke(prompt)\n"
        ),
    })
    assert any(f.sink_function == "handler" and f.source == "user_input" for f in flows)


def test_imported_alias(tmp_path: Path):
    flows = _flows(tmp_path, {
        "app.py": (
            "from service import process as run_model\n"
            "def handler(request):\n"
            "    return run_model(request.json['message'])\n"
        ),
        "service.py": (
            "def process(text):\n"
            "    return llm.invoke(text)\n"
        ),
    })
    assert any(f.file == "service.py" and f.source_file == "app.py" for f in flows)


def test_class_instance_method(tmp_path: Path):
    flows = _flows(tmp_path, {
        "svc.py": (
            "class Worker:\n"
            "    def run(self, text):\n"
            "        return llm.invoke(text)\n"
        ),
        "app.py": (
            "from svc import Worker\n"
            "def handler(request):\n"
            "    w = Worker()\n"
            "    return w.run(request.json['message'])\n"
        ),
    })
    assert any(f.sink_function == "run" and f.file == "svc.py" for f in flows)


def test_llm_wrapper_to_os_system(tmp_path: Path):
    flows = _flows(tmp_path, {
        "tools.py": (
            "import os\n"
            "def run_tool(cmd):\n"
            "    os.system(cmd)\n"
        ),
        "app.py": (
            "from tools import run_tool\n"
            "def handler(request):\n"
            "    run_tool(request.json['command'])\n"
        ),
    })
    assert any(f.sink_category == "rce" and f.file == "tools.py" for f in flows)


def test_sql_fstring_injection(tmp_path: Path):
    flows = _flows(tmp_path, {
        "db.py": (
            "def lookup(request):\n"
            "    q = request.json['id']\n"
            "    cursor.execute(f\"SELECT * FROM t WHERE id = '{q}'\")\n"
        ),
    })
    assert any(f.sink_category == "sql" for f in flows)


def test_no_flow_when_call_connected_but_value_not_passed(tmp_path: Path):
    flows = _flows(tmp_path, {
        "app.py": (
            "from service import process\n"
            "def handler(request):\n"
            "    _ignored = request.json['message']\n"
            "    return process('constant')\n"
        ),
        "service.py": (
            "def process(text):\n"
            "    return llm.invoke(text)\n"
        ),
    })
    assert not any(f.file == "service.py" and f.source == "user_input" for f in flows)


def test_unrelated_same_named_functions(tmp_path: Path):
    flows = _flows(tmp_path, {
        "app.py": (
            "def handler(request):\n"
            "    run(request.json['message'])\n"
            "def run(text):\n"
            "    return text\n"
        ),
        "other.py": (
            "def run(text):\n"
            "    return llm.invoke(text)\n"
        ),
    })
    assert not any(f.file == "other.py" for f in flows)


def test_tainted_arg_on_unrelated_parameter(tmp_path: Path):
    flows = _flows(tmp_path, {
        "app.py": (
            "def sink(safe, prompt):\n"
            "    return llm.invoke(prompt)\n"
            "def handler(request):\n"
            "    sink(request.json['message'], 'hello')\n"
        ),
    })
    assert not any(f.source == "user_input" for f in flows)


def test_constant_to_sink_without_source(tmp_path: Path):
    flows = _flows(tmp_path, {
        "app.py": (
            "def handler(request):\n"
            "    return llm.invoke('static prompt')\n"
        ),
    })
    assert flows == []


def test_safe_subprocess_argv_list(tmp_path: Path):
    flows = _flows(tmp_path, {
        "app.py": (
            "import subprocess\n"
            "def handler(request):\n"
            "    cmd = request.json['cmd']\n"
            "    subprocess.run([cmd], check=True)\n"
        ),
    })
    assert not any(f.sink_category == "rce" for f in flows)


def test_parameterized_sql_not_reported(tmp_path: Path):
    flows = _flows(tmp_path, {
        "app.py": (
            "def handler(request):\n"
            "    q = request.json['id']\n"
            "    cursor.execute('SELECT * FROM t WHERE id = ?', (q,))\n"
        ),
    })
    assert not any(f.sink_category == "sql" for f in flows)


def test_sanitized_input_not_reported(tmp_path: Path):
    flows = _flows(tmp_path, {
        "app.py": (
            "def handler(request):\n"
            "    raw = request.json['message']\n"
            "    clean = sanitize(raw)\n"
            "    return llm.invoke(clean)\n"
        ),
    })
    assert not any(f.source == "user_input" and not f.sanitized for f in flows)


def test_recursion_respects_iteration_limit(tmp_path: Path):
    flows = _flows(tmp_path, {
        "app.py": (
            "def loop(x):\n"
            "    return loop(x)\n"
            "def handler(request):\n"
            "    return loop(request.json['message'])\n"
        ),
    })
    assert isinstance(flows, list)


def test_two_call_sites_constant_does_not_inherit_taint(tmp_path: Path):
    """A constant call to a helper must not pick up another site's taint."""
    flows = _flows(tmp_path, {
        "app.py": (
            "def helper(text):\n"
            "    return llm.invoke(text)\n"
            "def handler(request):\n"
            "    helper(request.json['message'])\n"
            "    helper('constant prompt')\n"
        ),
    })
    assert any(
        f.source == "user_input" and f.sink_function == "helper" for f in flows
    )
    assert not any(f.source_function == "handler" and "constant" in (f.sink or "") for f in flows)
    tainted = [f for f in flows if f.source == "user_input" and f.sink_category == "llm"]
    assert len(tainted) == 1
    assert tainted[0].source_file == "app.py"


def test_two_callers_mixed_taint_return_not_shared(tmp_path: Path):
    """Return taint is per call-site context, not a function-wide union."""
    flows = _flows(tmp_path, {
        "app.py": (
            "def identity(x):\n"
            "    return x\n"
            "def handler(request):\n"
            "    a = identity(request.json['message'])\n"
            "    llm.invoke(a)\n"
            "    b = identity('ok')\n"
            "    os.system(b)\n"
        ),
    })
    assert any(f.sink_category == "llm" and f.source == "user_input" for f in flows)
    assert not any(f.sink_category == "rce" for f in flows)


def test_two_callers_two_sinks_only_tainted_context(tmp_path: Path):
    """Tainted caller reaches both sinks; constant caller does not create flows."""
    flows = _flows(tmp_path, {
        "helpers.py": (
            "import os\n"
            "def run_both(text):\n"
            "    llm.invoke(text)\n"
            "    os.system(text)\n"
        ),
        "app.py": (
            "from helpers import run_both\n"
            "def unsafe(request):\n"
            "    run_both(request.json['cmd'])\n"
            "def safe():\n"
            "    run_both('echo hi')\n"
        ),
    })
    cats = {(f.sink_category, f.source) for f in flows}
    assert ("llm", "user_input") in cats
    assert ("rce", "user_input") in cats
    assert not any(f.source_function == "safe" for f in flows)
    assert all(f.source_file == "app.py" for f in flows if f.source == "user_input")


def test_call_order_constant_first_then_tainted(tmp_path: Path):
    """Union-by-iteration-order must not taint the constant site's return use."""
    flows = _flows(tmp_path, {
        "app.py": (
            "def wrap(text):\n"
            "    return text\n"
            "def handler(request):\n"
            "    safe = wrap('static')\n"
            "    llm.invoke(safe)\n"
            "    bad = wrap(request.json['message'])\n"
            "    os.system(bad)\n"
        ),
    })
    assert any(f.sink_category == "rce" and f.source == "user_input" for f in flows)
    assert not any(f.sink_category == "llm" for f in flows)


def test_unresolved_import_does_not_fabricate_edge(tmp_path: Path):
    flows = _flows(tmp_path, {
        "app.py": (
            "from missing_pkg.deep import explode\n"
            "def handler(request):\n"
            "    return explode(request.json['message'])\n"
        ),
    })
    assert flows == []


def test_ainvoke_async_handler(tmp_path: Path):
    flows = _flows(tmp_path, {
        "app.py": (
            "async def handler(request):\n"
            "    value = request.json['message']\n"
            "    return await llm.ainvoke(value)\n"
        ),
    })
    assert any(f.sink_category == "llm" and f.source == "user_input" for f in flows)


def test_aliased_openai_import(tmp_path: Path):
    flows = _flows(tmp_path, {
        "app.py": (
            "import openai as o\n"
            "def handler(request):\n"
            "    o.chat.completions.create(messages=request.json['message'])\n"
        ),
    })
    assert any(f.sink_category == "llm" and f.source == "user_input" for f in flows)


def test_module_qualified_provider_call(tmp_path: Path):
    flows = _flows(tmp_path, {
        "app.py": (
            "import openai\n"
            "def handler(request):\n"
            "    openai.chat.completions.create(messages=request.json['message'])\n"
        ),
    })
    assert any(f.sink_category == "llm" and f.source == "user_input" for f in flows)


def test_langchain_invoke_still_detected(tmp_path: Path):
    flows = _flows(tmp_path, {
        "app.py": (
            "def handler(request):\n"
            "    return chain.invoke(request.json['message'])\n"
        ),
    })
    assert any(f.sink_category == "llm" for f in flows)


def test_in_repo_llm_wrapper_resolved(tmp_path: Path):
    """Wrapper is not itself a sink; taint follows the resolved body."""
    flows = _flows(tmp_path, {
        "client.py": (
            "import openai\n"
            "def ask(prompt):\n"
            "    return openai.chat.completions.create(messages=prompt)\n"
        ),
        "app.py": (
            "from client import ask\n"
            "def handler(request):\n"
            "    return ask(request.json['message'])\n"
        ),
    })
    assert any(
        f.sink_category == "llm" and f.file == "client.py" and f.source_file == "app.py"
        for f in flows
    )


def test_unrelated_invoke_and_chat_are_not_llm_sinks(tmp_path: Path):
    flows = _flows(tmp_path, {
        "app.py": (
            "class Router:\n"
            "    def invoke(self, payload):\n"
            "        return payload\n"
            "    def chat(self, payload):\n"
            "        return payload\n"
            "def handler(request):\n"
            "    r = Router()\n"
            "    r.invoke(request.json['message'])\n"
            "    r.chat(request.json['message'])\n"
        ),
    })
    assert not any(f.sink_category == "llm" for f in flows)


def test_unresolved_wrapper_is_not_fabricated_sink(tmp_path: Path):
    """External ask_llm() is not treated as an LLM sink without a resolved body."""
    flows = _flows(tmp_path, {
        "app.py": (
            "from vendor import ask_llm\n"
            "def handler(request):\n"
            "    return ask_llm(request.json['message'])\n"
        ),
    })
    assert flows == []


def test_module_qualified_local_import(tmp_path: Path):
    flows = _flows(tmp_path, {
        "app.py": (
            "import service\n"
            "def handler(request):\n"
            "    return service.process(request.json['message'])\n"
        ),
        "service.py": (
            "def process(text):\n"
            "    return llm.invoke(text)\n"
        ),
    })
    assert any(f.file == "service.py" and f.source_file == "app.py" for f in flows)


def test_self_method_call(tmp_path: Path):
    flows = _flows(tmp_path, {
        "app.py": (
            "class Bot:\n"
            "    def send(self, text):\n"
            "        return llm.invoke(text)\n"
            "    def handle(self, request):\n"
            "        return self.send(request.json['message'])\n"
        ),
    })
    assert any(f.sink_function == "send" and f.source == "user_input" for f in flows)


def test_nested_function_with_parameter(tmp_path: Path):
    flows = _flows(tmp_path, {
        "app.py": (
            "def handler(request):\n"
            "    def inner(p):\n"
            "        return llm.invoke(p)\n"
            "    return inner(request.json['message'])\n"
        ),
    })
    assert any(f.sink_function == "inner" and f.source == "user_input" for f in flows)


def test_nested_closure_without_parameter_unsupported(tmp_path: Path):
    """Limitation: free variables in nested defs are not tracked as taint."""
    flows = _flows(tmp_path, {
        "app.py": (
            "def handler(request):\n"
            "    x = request.json['message']\n"
            "    def inner():\n"
            "        return llm.invoke(x)\n"
            "    return inner()\n"
        ),
    })
    assert not any(f.sink_function == "inner" for f in flows)


def test_dict_other_key_is_field_insensitive(tmp_path: Path):
    """Limitation: extraction is not key-sensitive; d['q'] still sees taint on d."""
    flows = _flows(tmp_path, {
        "app.py": (
            "def handler(request):\n"
            "    d = {'p': request.json['message'], 'q': 'ok'}\n"
            "    return llm.invoke(d['q'])\n"
        ),
    })
    assert any(f.sink_category == "llm" and f.source == "user_input" for f in flows)


def test_dict_and_list_container_name_taint(tmp_path: Path):
    """Field-insensitive: taint follows the container name, not dictionary keys."""
    flows = _flows(tmp_path, {
        "app.py": (
            "def handler(request):\n"
            "    d = {'p': request.json['message']}\n"
            "    llm.invoke(d['p'])\n"
            "    items = [request.json['message']]\n"
            "    os.system(items[0])\n"
        ),
    })
    assert any(f.sink_category == "llm" for f in flows)
    assert any(f.sink_category == "rce" for f in flows)


def test_instance_attribute_taint_same_method(tmp_path: Path):
    """Uses a field name that is not itself a source pattern (not 'prompt')."""
    flows = _flows(tmp_path, {
        "app.py": (
            "class Worker:\n"
            "    def handle(self, request):\n"
            "        self.blob = request.json['message']\n"
            "        return llm.invoke(self.blob)\n"
        ),
    })
    assert any(f.sink_category == "llm" and f.source == "user_input" for f in flows)


def test_instance_attribute_cross_method_unsupported(tmp_path: Path):
    """Limitation: self.blob is not an object-sensitive field summary across methods."""
    flows = _flows(tmp_path, {
        "app.py": (
            "class Worker:\n"
            "    def set_blob(self, text):\n"
            "        self.blob = text\n"
            "    def run(self):\n"
            "        return llm.invoke(self.blob)\n"
            "def handler(request):\n"
            "    w = Worker()\n"
            "    w.set_blob(request.json['message'])\n"
            "    w.run()\n"
        ),
    })
    assert not any(f.sink_function == "run" for f in flows)


def test_overwrite_with_constant_kills_taint(tmp_path: Path):
    flows = _flows(tmp_path, {
        "app.py": (
            "def handler(request):\n"
            "    x = request.json['message']\n"
            "    x = 'ok'\n"
            "    llm.invoke(x)\n"
        ),
    })
    assert not any(f.sink_category == "llm" for f in flows)


def test_overwrite_with_untainted_name_kills_taint(tmp_path: Path):
    flows = _flows(tmp_path, {
        "app.py": (
            "def handler(request):\n"
            "    x = request.json['message']\n"
            "    y = 'ok'\n"
            "    x = y\n"
            "    llm.invoke(x)\n"
        ),
    })
    assert not any(f.sink_category == "llm" for f in flows)


def test_tainted_assignment_still_propagates(tmp_path: Path):
    flows = _flows(tmp_path, {
        "app.py": (
            "def handler(request):\n"
            "    x = request.json['message']\n"
            "    y = x\n"
            "    llm.invoke(y)\n"
        ),
    })
    assert any(f.sink_category == "llm" and f.source == "user_input" for f in flows)


def test_multiple_assignments_preserve_only_latest_straight_line_state(tmp_path: Path):
    flows = _flows(tmp_path, {
        "app.py": (
            "def handler(request):\n"
            "    x = 'ok'\n"
            "    llm.invoke(x)\n"
            "    x = request.json['message']\n"
            "    os.system(x)\n"
        ),
    })
    assert not any(f.sink_category == "llm" for f in flows)
    assert any(f.sink_category == "rce" and f.source == "user_input" for f in flows)


def test_unrelated_attr_prompt_not_source(tmp_path: Path):
    flows = _flows(tmp_path, {
        "app.py": (
            "def handler():\n"
            "    llm.invoke(config.prompt)\n"
        ),
    })
    assert flows == []


def test_unrelated_attr_message_not_source(tmp_path: Path):
    flows = _flows(tmp_path, {
        "app.py": (
            "def handler():\n"
            "    llm.invoke(template.message)\n"
            "    llm.invoke(obj.query)\n"
            "    llm.invoke(cfg.input)\n"
            "    llm.invoke(doc.text)\n"
            "    llm.invoke(item.content)\n"
        ),
    })
    assert flows == []


def test_get_input_not_user_source(tmp_path: Path):
    flows = _flows(tmp_path, {
        "app.py": (
            "def handler():\n"
            "    llm.invoke(get_input())\n"
        ),
    })
    assert not any(f.source == "user_input" for f in flows)


def test_session_query_not_user_input(tmp_path: Path):
    flows = _flows(tmp_path, {
        "app.py": (
            "def handler():\n"
            "    llm.invoke(session.query())\n"
        ),
    })
    assert not any(f.source == "user_input" for f in flows)


def test_request_json_remains_source(tmp_path: Path):
    flows = _flows(tmp_path, {
        "app.py": (
            "def handler(request):\n"
            "    llm.invoke(request.json['message'])\n"
        ),
    })
    assert any(f.source == "user_input" and f.sink_category == "llm" for f in flows)


def test_body_message_remains_source(tmp_path: Path):
    flows = _flows(tmp_path, {
        "app.py": (
            "def handler(body):\n"
            "    llm.invoke(body.message)\n"
        ),
    })
    assert any(f.source == "user_input" and f.sink_category == "llm" for f in flows)


def test_builtin_input_remains_source(tmp_path: Path):
    flows = _flows(tmp_path, {
        "app.py": (
            "def handler():\n"
            "    llm.invoke(input())\n"
        ),
    })
    assert any(f.source == "user_input" and f.sink_category == "llm" for f in flows)


def test_sanitize_inside_if_does_not_prove_post_if_safe(tmp_path: Path):
    flows = _flows(tmp_path, {
        "app.py": (
            "def handler(request):\n"
            "    x = request.json['message']\n"
            "    if cond:\n"
            "        x = sanitize(x)\n"
            "    llm.invoke(x)\n"
        ),
    })
    assert any(f.sink_category == "llm" and f.source == "user_input" for f in flows)


def test_sanitize_inside_try_does_not_prove_post_try_safe(tmp_path: Path):
    flows = _flows(tmp_path, {
        "app.py": (
            "def handler(request):\n"
            "    x = request.json['message']\n"
            "    try:\n"
            "        x = sanitize(x)\n"
            "    except Exception:\n"
            "        pass\n"
            "    llm.invoke(x)\n"
        ),
    })
    assert any(f.sink_category == "llm" and f.source == "user_input" for f in flows)


def test_straight_line_sanitizer_behavior_unchanged(tmp_path: Path):
    flows = _flows(tmp_path, {
        "app.py": (
            "def handler(request):\n"
            "    raw = request.json['message']\n"
            "    clean = sanitize(raw)\n"
            "    return llm.invoke(clean)\n"
        ),
    })
    assert not any(f.source == "user_input" and not f.sanitized for f in flows)


def test_context_cap_sets_incomplete_marker(tmp_path: Path):
    lines = [
        "def h(x):\n",
        "    llm.invoke(x)\n",
        "def f(request):\n",
    ]
    for i in range(6):
        lines.append(f"    h(request.json['k{i}'])\n")
    result = _result(tmp_path, {"app.py": "".join(lines)}, max_contexts_per_func=2)
    assert result.incomplete is True
    assert "context_cap" in result.incomplete_reasons
    assert all(f.confidence == "may" for f in result.data_flows)


def test_iteration_cap_sets_incomplete_marker(tmp_path: Path):
    result = _result(tmp_path, {
        "app.py": (
            "def z(x):\n"
            "    llm.invoke(x)\n"
            "def y(x):\n"
            "    return z(x)\n"
            "def xfn(x):\n"
            "    return y(x)\n"
            "def handler(request):\n"
            "    xfn(request.json['message'])\n"
        ),
    }, max_iters=1)
    assert result.incomplete is True
    assert "iteration_cap" in result.incomplete_reasons


def test_request_get_json_or_empty_then_dict_get(tmp_path: Path):
    flows = _flows(tmp_path, {
        "app.py": (
            "def handler(request):\n"
            "    data = request.get_json(force=True, silent=True) or {}\n"
            "    message = data.get('message', '')\n"
            "    llm.invoke(message)\n"
        ),
    })
    assert any(f.source == "user_input" and f.sink_category == "llm" for f in flows)


def test_chained_get_json_get_message(tmp_path: Path):
    flows = _flows(tmp_path, {
        "app.py": (
            "def handler(request):\n"
            "    llm.invoke(request.get_json().get('message'))\n"
        ),
    })
    assert any(f.source == "user_input" and f.sink_category == "llm" for f in flows)


def test_unrelated_dict_get_not_source(tmp_path: Path):
    flows = _flows(tmp_path, {
        "app.py": (
            "def handler():\n"
            "    settings = {'message': 'hello'}\n"
            "    llm.invoke(settings.get('message'))\n"
        ),
    })
    assert not any(f.source == "user_input" for f in flows)


def test_request_args_query_param_still_source(tmp_path: Path):
    flows = _flows(tmp_path, {
        "app.py": (
            "def handler(request):\n"
            "    llm.invoke(request.args.get('q', ''))\n"
        ),
    })
    assert any(f.source == "user_input" and f.sink_category == "llm" for f in flows)


def test_list_append_then_llm_wrapper(tmp_path: Path):
    """run_agent-style: taint is appended onto messages after construction."""
    flows = _flows(tmp_path, {
        "app.py": (
            "import requests\n"
            "def chat(messages):\n"
            "    requests.post('http://localhost:11434/api/chat', json={'messages': messages})\n"
            "def run_agent(user_message):\n"
            "    messages = [{'role': 'system', 'content': 'hi'}]\n"
            "    messages.append({'role': 'user', 'content': user_message})\n"
            "    return chat(messages)\n"
            "def handler(request):\n"
            "    data = request.get_json() or {}\n"
            "    run_agent(data.get('message'))\n"
        ),
    })
    assert any(f.sink_category == "llm" and f.source == "user_input" for f in flows)


def test_json_body_to_agent_to_ollama_chat(tmp_path: Path):
    flows = _flows(tmp_path, {
        "api.py": (
            "from agent import run_agent\n"
            "def handler(request):\n"
            "    data = request.get_json() or {}\n"
            "    message = data.get('message', '')\n"
            "    return run_agent(message)\n"
        ),
        "agent.py": (
            "from llm import chat\n"
            "def run_agent(user_message):\n"
            "    messages = [{'role': 'user', 'content': user_message}]\n"
            "    return chat(messages)\n"
        ),
        "llm.py": (
            "import requests\n"
            "def chat(messages):\n"
            "    return _ollama_chat(messages)\n"
            "def _ollama_chat(messages):\n"
            "    payload = {'model': 'llama3', 'messages': messages}\n"
            "    return requests.post('http://localhost:11434/api/chat', json=payload)\n"
        ),
    })
    hits = [f for f in flows if f.sink_category == "llm" and f.source == "user_input"]
    assert hits
    f = hits[0]
    assert f.file == "llm.py"
    assert "ollama" in f.sink.lower() or "/api/chat" in f.sink
    hops = " ".join(f.hops)
    assert "api.py" in hops and "agent.py" in hops and "llm.py" in hops


def test_tainted_and_constant_args_same_ollama_wrapper(tmp_path: Path):
    flows = _flows(tmp_path, {
        "app.py": (
            "import requests\n"
            "def talk(messages):\n"
            "    requests.post('http://localhost:11434/api/chat', json={'messages': messages})\n"
            "def handler(request):\n"
            "    data = request.get_json() or {}\n"
            "    talk(data.get('message'))\n"
            "    talk('hello')\n"
        ),
    })
    assert any(f.source == "user_input" and f.sink_category == "llm" for f in flows)
    assert not any(f.source_function == "handler" and f.sink_category == "llm" and "hello" in f.sink for f in flows)


def test_flask_chat_handler_is_not_llm_sink(tmp_path: Path):
    flows = _flows(tmp_path, {
        "app.py": (
            "def chat():\n"
            "    return {'ok': True}\n"
            "def handler(request):\n"
            "    data = request.get_json() or {}\n"
            "    return chat()\n"
        ),
    })
    assert not any(f.sink_category == "llm" for f in flows)


def test_unrelated_requests_post_is_not_llm_sink(tmp_path: Path):
    flows = _flows(tmp_path, {
        "app.py": (
            "import requests\n"
            "def handler(request):\n"
            "    data = request.get_json() or {}\n"
            "    requests.post('https://example.com/hooks', json={'message': data.get('message')})\n"
        ),
    })
    assert not any(f.sink_category == "llm" for f in flows)


def test_unresolved_chat_wrapper_not_fabricated(tmp_path: Path):
    flows = _flows(tmp_path, {
        "app.py": (
            "from vendor import chat\n"
            "def handler(request):\n"
            "    data = request.get_json() or {}\n"
            "    return chat(data.get('message'))\n"
        ),
    })
    assert flows == []


def test_sqlalchemy_text_execute_taint(tmp_path: Path):
    flows = _flows(tmp_path, {
        "db.py": (
            "def ask(request):\n"
            "    data = request.get_json() or {}\n"
            "    sql = data.get('question')\n"
            "    db.session.execute(text(sql))\n"
        ),
    })
    assert any(f.sink_category == "sql" and f.source == "user_input" for f in flows)


def test_sqlalchemy_constant_sql_not_taint(tmp_path: Path):
    flows = _flows(tmp_path, {
        "db.py": (
            "def ask(request):\n"
            "    db.session.execute(text('SELECT 1'))\n"
        ),
    })
    assert not any(f.sink_category == "sql" for f in flows)


def test_unrelated_execute_not_sql_taint(tmp_path: Path):
    flows = _flows(tmp_path, {
        "app.py": (
            "def handler(request):\n"
            "    data = request.get_json() or {}\n"
            "    widget.execute(data.get('command'))\n"
        ),
    })
    assert not any(f.sink_category == "sql" for f in flows)


def test_complete_analysis_not_marked_incomplete(tmp_path: Path):
    result = _result(tmp_path, {
        "app.py": (
            "def handler(request):\n"
            "    llm.invoke(request.json['message'])\n"
        ),
    })
    assert result.incomplete is False
    assert result.incomplete_reasons == []
    assert all(f.confidence == "high" for f in result.data_flows)


def test_lookup_id_field_in_fixed_prompt_is_not_request_payload(tmp_path: Path):
    """ID used only to load a record must not count as request payload in the LLM."""
    flows = _flows(tmp_path, {
        "app.py": (
            "def handler(request):\n"
            "    record_id = request.json['id']\n"
            "    obj = repository.load(record_id)\n"
            "    llm.invoke(f'Brief {obj.title}')\n"
        ),
    })
    assert not any(f.sink_category == "llm" and f.source == "user_input" for f in flows)


def test_request_message_to_llm_is_payload(tmp_path: Path):
    flows = _flows(tmp_path, {
        "app.py": (
            "def handler(request):\n"
            "    message = request.json['message']\n"
            "    llm.invoke(message)\n"
        ),
    })
    hits = [f for f in flows if f.sink_category == "llm" and f.source == "user_input"]
    assert hits
    assert all(getattr(f, "taint_kind", "payload") == "payload" for f in hits)


def test_request_message_in_fstring_to_llm_is_payload(tmp_path: Path):
    flows = _flows(tmp_path, {
        "app.py": (
            "def handler(request):\n"
            "    message = request.json['message']\n"
            "    llm.invoke(f'q={message}')\n"
        ),
    })
    hits = [f for f in flows if f.sink_category == "llm" and f.source == "user_input"]
    assert hits
    assert all(getattr(f, "taint_kind", "payload") == "payload" for f in hits)


def test_constant_overwrite_drops_stale_taint(tmp_path: Path):
    flows = _flows(tmp_path, {
        "app.py": (
            "def handler(request):\n"
            "    x = request.json['message']\n"
            "    x = 'constant'\n"
            "    llm.invoke(x)\n"
        ),
    })
    assert not any(f.sink_category == "llm" for f in flows)


def test_sanitize_in_one_branch_does_not_clear_other_path(tmp_path: Path):
    flows = _flows(tmp_path, {
        "app.py": (
            "def handler(request):\n"
            "    x = request.json['message']\n"
            "    if cond:\n"
            "        x = sanitize(x)\n"
            "    else:\n"
            "        x = x\n"
            "    llm.invoke(x)\n"
        ),
    })
    assert any(f.sink_category == "llm" and f.source == "user_input" for f in flows)


def test_cross_file_arg_and_return_still_propagate(tmp_path: Path):
    flows = _flows(tmp_path, {
        "app.py": (
            "from service import wrap, sink\n"
            "def handler(request):\n"
            "    value = request.json['message']\n"
            "    return sink(wrap(value))\n"
        ),
        "service.py": (
            "def wrap(text):\n"
            "    return text\n"
            "def sink(prompt):\n"
            "    return llm.invoke(prompt)\n"
        ),
    })
    assert any(
        f.sink_category == "llm"
        and f.source == "user_input"
        and f.file == "service.py"
        and f.source_file == "app.py"
        for f in flows
    )


def test_unresolved_transform_is_not_confirmed_value_taint(tmp_path: Path):
    """Taint must not jump through an unresolved call onto a later sink argument."""
    flows = _flows(tmp_path, {
        "app.py": (
            "from vendor import transform\n"
            "def handler(request):\n"
            "    msg = request.json['message']\n"
            "    x = transform(msg)\n"
            "    return llm.invoke(x)\n"
        ),
    })
    assert not any(f.sink_category == "llm" and f.source == "user_input" for f in flows)
