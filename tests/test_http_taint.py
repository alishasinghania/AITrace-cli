"""HTTP sink classification, argument roles, and FLOW-HTTP promotion."""
from __future__ import annotations

import ast
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from core.analyzers.dataflow_analyzer import analyze_dataflows
from core.analyzers.crossfile_taint import analyze_crossfile_taint
from core.analyzers.pattern_analyzer import analyze_patterns
from core.analyzers.taint_catalog import classify_sink


def _write(tmp: Path, files: dict) -> Path:
    for name, src in files.items():
        p = tmp / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(src, encoding="utf-8")
    return tmp


def _flows(tmp: Path, files: dict):
    return analyze_dataflows(_write(tmp, files)).data_flows


def _promote(tmp: Path, files: dict):
    root = _write(tmp, files)
    flows = analyze_dataflows(root)
    patterns = analyze_patterns(root)
    analyze_crossfile_taint(root, patterns.findings, data_flows=flows.data_flows)
    return patterns.findings, flows.data_flows


def _http(flows):
    return [f for f in flows if f.sink_category == "http"]


# ---------------------------------------------------------------------------
# Taxonomy
# ---------------------------------------------------------------------------

def test_requests_get_is_http_sink():
    node = ast.parse("requests.get(url)").body[0].value
    assert "http" in classify_sink(node)


def test_httpx_post_is_http_sink():
    node = ast.parse("httpx.post(url, json=body)").body[0].value
    assert "http" in classify_sink(node)


def test_widget_get_is_not_http_sink():
    node = ast.parse("widget.get(url)").body[0].value
    assert "http" not in classify_sink(node)


def test_widget_post_request_send_are_not_http_sinks():
    for src in ("obj.post(x)", "obj.request(x)", "obj.send(x)", "cache.get(key)"):
        node = ast.parse(src).body[0].value
        assert "http" not in classify_sink(node), src


def test_flask_request_get_json_is_not_outbound_http():
    node = ast.parse("request.get_json()").body[0].value
    assert "http" not in classify_sink(node)


# ---------------------------------------------------------------------------
# Value-taint DataFlows and promotion
# ---------------------------------------------------------------------------

def test_direct_request_as_outbound_url(tmp_path: Path):
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "import requests\n"
            "def handler(request):\n"
            "    target = request.json['url']\n"
            "    requests.get(target)\n"
        ),
    })
    hits = [f for f in _http(flows) if f.source == "user_input"]
    assert hits
    assert all(getattr(f, "sink_arg_role", "") == "url" for f in hits)
    assert any(f.vulnerability_id == "FLOW-HTTP" for f in findings)
    assert all(getattr(f, "taint_kind", "payload") == "payload" for f in hits)


def test_interpolated_url_string(tmp_path: Path):
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "import requests\n"
            "def handler(request):\n"
            "    host = request.json['host']\n"
            "    requests.get(f'https://{host}/v1')\n"
        ),
    })
    assert any(f.sink_category == "http" and getattr(f, "sink_arg_role", "") == "url" for f in flows)
    assert any(f.vulnerability_id == "FLOW-HTTP" for f in findings)


def test_cross_file_url_helper(tmp_path: Path):
    findings, flows = _promote(tmp_path, {
        "build.py": (
            "def make_url(request):\n"
            "    host = request.json['host']\n"
            "    return f'https://{host}/items'\n"
        ),
        "client.py": (
            "import requests\n"
            "from build import make_url\n"
            "def fetch(request):\n"
            "    requests.get(make_url(request))\n"
        ),
    })
    hits = [f for f in _http(flows) if f.file == "client.py"]
    assert hits
    assert any(getattr(f, "sink_arg_role", "") == "url" for f in hits)
    assert any(f.vulnerability_id == "FLOW-HTTP" and f.file == "client.py" for f in findings)


def test_json_body_only_is_not_ssrf_finding(tmp_path: Path):
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "import requests\n"
            "def handler(request):\n"
            "    msg = request.json['message']\n"
            "    requests.post('https://example.com/hooks', json={'message': msg})\n"
        ),
    })
    hits = [f for f in _http(flows) if f.source == "user_input"]
    assert hits
    assert all(getattr(f, "sink_arg_role", "") == "body" for f in hits)
    assert not any(f.vulnerability_id == "FLOW-HTTP" for f in findings)
    assert not any(f.sink_category == "llm" for f in flows)


def test_header_only_is_not_ssrf_finding(tmp_path: Path):
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "import requests\n"
            "def handler(request):\n"
            "    token = request.json['token']\n"
            "    requests.get('https://example.com/me', headers={'Authorization': token})\n"
        ),
    })
    hits = [f for f in _http(flows) if f.source == "user_input"]
    assert hits
    assert all(getattr(f, "sink_arg_role", "") == "headers" for f in hits)
    assert not any(f.vulnerability_id == "FLOW-HTTP" for f in findings)


def test_constant_url_tainted_body(tmp_path: Path):
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "import httpx\n"
            "def handler(request):\n"
            "    payload = request.json['body']\n"
            "    httpx.post('https://api.example.com/v1', json=payload)\n"
        ),
    })
    hits = _http(flows)
    assert hits
    assert all(getattr(f, "sink_arg_role", "") == "body" for f in hits)
    assert not any(f.vulnerability_id == "FLOW-HTTP" for f in findings)


def test_unrelated_get_post_send_not_http_taint(tmp_path: Path):
    flows = _flows(tmp_path, {
        "app.py": (
            "class Store:\n"
            "    def get(self, key):\n"
            "        return key\n"
            "    def post(self, key):\n"
            "        return key\n"
            "    def request(self, key):\n"
            "        return key\n"
            "    def send(self, key):\n"
            "        return key\n"
            "def handler(request):\n"
            "    s = Store()\n"
            "    x = request.json['x']\n"
            "    s.get(x)\n"
            "    s.post(x)\n"
            "    s.request(x)\n"
            "    s.send(x)\n"
        ),
    })
    assert not any(f.sink_category == "http" for f in flows)


def test_unresolved_wrapper_around_url_not_confirmed(tmp_path: Path):
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "import requests\n"
            "from vendor import transform\n"
            "def handler(request):\n"
            "    raw = request.json['url']\n"
            "    target = transform(raw)\n"
            "    requests.get(target)\n"
        ),
    })
    assert not any(f.sink_category == "http" and f.source == "user_input" for f in flows)
    assert not any(f.vulnerability_id == "FLOW-HTTP" for f in findings)


def test_http_call_without_taint_has_no_flow(tmp_path: Path):
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "import requests\n"
            "def handler():\n"
            "    requests.get('https://example.com/health')\n"
        ),
    })
    assert not _http(flows)
    assert not any(f.vulnerability_id == "FLOW-HTTP" for f in findings)


def test_ollama_chat_remains_llm_not_http(tmp_path: Path):
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "import requests\n"
            "def handler(request):\n"
            "    msg = request.json['message']\n"
            "    requests.post('http://localhost:11434/api/chat', json={'messages': msg})\n"
        ),
    })
    assert any(f.sink_category == "llm" and f.source == "user_input" for f in flows)
    assert not any(f.sink_category == "http" for f in flows)
    assert any(f.vulnerability_id == "FLOW-LLM" for f in findings)
    assert not any(f.vulnerability_id == "FLOW-HTTP" for f in findings)


def test_two_http_url_sinks_are_separate(tmp_path: Path):
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "import requests\n"
            "def handler(request):\n"
            "    a = request.json['a']\n"
            "    b = request.json['b']\n"
            "    requests.get(a)\n"
            "    requests.get(b)\n"
        ),
    })
    url_flows = [f for f in _http(flows) if getattr(f, "sink_arg_role", "") == "url"]
    assert len({f.line for f in url_flows}) >= 2
    http_findings = [f for f in findings if f.vulnerability_id == "FLOW-HTTP"]
    assert len({f.line for f in http_findings}) >= 2


def test_one_source_reaches_http_url_and_rce(tmp_path: Path):
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "import os\n"
            "import requests\n"
            "def handler(request):\n"
            "    x = request.json['x']\n"
            "    requests.get(x)\n"
            "    os.system(x)\n"
        ),
    })
    cats = {f.sink_category for f in flows}
    assert "http" in cats and "rce" in cats
    ids = {f.vulnerability_id for f in findings}
    assert "FLOW-HTTP" in ids
    assert "FLOW-RCE" in ids or "PAT-025" in ids


def test_requests_alias_preserves_http_classification(tmp_path: Path):
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "import requests as req\n"
            "def handler(request):\n"
            "    target = request.json['url']\n"
            "    req.get(target)\n"
        ),
    })
    assert any(f.sink_category == "http" and getattr(f, "sink_arg_role", "") == "url" for f in flows)
    assert any(f.vulnerability_id == "FLOW-HTTP" for f in findings)


def test_starred_kwargs_do_not_assert_ssrf(tmp_path: Path):
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "import requests\n"
            "def handler(request):\n"
            "    payload = request.json\n"
            "    requests.post(**payload)\n"
        ),
    })
    assert not any(f.vulnerability_id == "FLOW-HTTP" for f in findings)
    http_flows = _http(flows)
    assert not http_flows or all(getattr(f, "sink_arg_role", "") == "unresolved" for f in http_flows)


def test_query_params_are_not_ssrf_finding(tmp_path: Path):
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "import requests\n"
            "def handler(request):\n"
            "    q = request.json['q']\n"
            "    requests.get('https://example.com/search', params={'q': q})\n"
        ),
    })
    hits = _http(flows)
    assert hits
    assert all(getattr(f, "sink_arg_role", "") == "query" for f in hits)
    assert not any(f.vulnerability_id == "FLOW-HTTP" for f in findings)


def test_session_client_get_tracks_url(tmp_path: Path):
    flows = _flows(tmp_path, {
        "app.py": (
            "import requests\n"
            "def handler(request):\n"
            "    target = request.json['url']\n"
            "    s = requests.Session()\n"
            "    s.get(target)\n"
        ),
    })
    assert any(f.sink_category == "http" and getattr(f, "sink_arg_role", "") == "url" for f in flows)


def test_lookup_id_not_http_payload_via_url(tmp_path: Path):
    """Fetched object field in a constant URL query is not request-payload URL taint."""
    flows = _flows(tmp_path, {
        "app.py": (
            "import requests\n"
            "def handler(request):\n"
            "    record_id = request.json['id']\n"
            "    obj = repository.load(record_id)\n"
            "    requests.get(f'https://example.com/x')\n"
        ),
    })
    assert not any(f.sink_category == "http" and f.source == "user_input" for f in flows)
