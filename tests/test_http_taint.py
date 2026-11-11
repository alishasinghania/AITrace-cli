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

def test_request_args_url_is_flow_http(tmp_path: Path):
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "import requests\n"
            "def handler(request):\n"
            "    url = request.args['url']\n"
            "    requests.get(url)\n"
        ),
    })
    hits = [f for f in _http(flows) if f.source == "user_input"]
    assert hits
    assert all(getattr(f, "sink_arg_role", "") == "url" for f in hits)
    http_findings = [f for f in findings if f.vulnerability_id == "FLOW-HTTP"]
    assert http_findings
    assert any(f.confirmed_by_taint for f in http_findings)
    assert any(f.confidence != "may" for f in http_findings)


def test_function_parameter_to_post_url_is_flow_http(tmp_path: Path):
    """Parameter reaching a URL is a potential FLOW-HTTP, not attacker proof."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "import requests\n"
            "def notify(webhook_url):\n"
            "    requests.post(webhook_url, json={'ok': True})\n"
        ),
    })
    hits = [f for f in _http(flows) if getattr(f, "sink_arg_role", "") == "url"]
    assert hits
    assert all(f.source == "function_param" for f in hits)
    assert all(f.confidence == "may" for f in hits)
    http_findings = [f for f in findings if f.vulnerability_id == "FLOW-HTTP"]
    assert http_findings
    assert all(f.confidence == "may" for f in http_findings)
    assert all(not f.confirmed_by_taint for f in http_findings)
    assert any(
        "potential destination-control" in " ".join(f.evidence)
        for f in http_findings
    )


def test_function_parameter_aliased_to_post_url_is_flow_http(tmp_path: Path):
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "import requests\n"
            "def notify(webhook_url):\n"
            "    dest = webhook_url\n"
            "    requests.post(dest, json={'ok': True})\n"
        ),
    })
    assert any(f.vulnerability_id == "FLOW-HTTP" for f in findings)


def test_httpx_get_request_args_url_is_flow_http(tmp_path: Path):
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "import httpx\n"
            "def handler(request):\n"
            "    target = request.args['url']\n"
            "    httpx.get(target)\n"
        ),
    })
    assert any(f.sink_category == "http" and getattr(f, "sink_arg_role", "") == "url" for f in flows)
    assert any(f.vulnerability_id == "FLOW-HTTP" for f in findings)


def test_httpx_post_parameter_url_is_flow_http(tmp_path: Path):
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "import httpx\n"
            "def notify(webhook_url):\n"
            "    httpx.post(webhook_url, json={'ok': True})\n"
        ),
    })
    assert any(f.vulnerability_id == "FLOW-HTTP" for f in findings)


def test_httpx_client_get_tracks_url(tmp_path: Path):
    flows = _flows(tmp_path, {
        "app.py": (
            "import httpx\n"
            "def handler(request):\n"
            "    target = request.json['url']\n"
            "    client = httpx.Client()\n"
            "    client.get(target)\n"
        ),
    })
    assert any(f.sink_category == "http" and getattr(f, "sink_arg_role", "") == "url" for f in flows)


def test_sql_from_parameter_alone_is_not_flow_sql(tmp_path: Path):
    """Parameter seeding is HTTP-URL only and must not invent FLOW-SQL."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "def search(term):\n"
            "    cursor.execute(f\"SELECT * FROM t WHERE name='{term}'\")\n"
        ),
    })
    assert not any(f.sink_category == "sql" for f in flows)
    assert not any(f.vulnerability_id == "FLOW-SQL" for f in findings)


def test_rce_from_parameter_alone_is_not_flow_rce(tmp_path: Path):
    """function_param must not invent FLOW-RCE."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "import os\n"
            "def run(cmd):\n"
            "    os.system(cmd)\n"
        ),
    })
    assert not any(f.sink_category == "rce" for f in flows)
    assert not any(f.vulnerability_id == "FLOW-RCE" for f in findings)


def test_llm_from_parameter_alone_is_not_flow_llm(tmp_path: Path):
    """function_param must not invent FLOW-LLM."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "import requests\n"
            "def ask(msg):\n"
            "    requests.post('http://localhost:11434/api/chat', json={'messages': msg})\n"
        ),
    })
    assert not any(f.sink_category == "llm" for f in flows)
    assert not any(f.vulnerability_id == "FLOW-LLM" for f in findings)
    assert not any(f.vulnerability_id == "FLOW-HTTP" for f in findings)


def test_http_body_from_parameter_is_not_ssrf(tmp_path: Path):
    """Parameter taint in the HTTP body is not destination control."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "import requests\n"
            "def notify(payload):\n"
            "    requests.post('https://example.com/hooks', json=payload)\n"
        ),
    })
    assert not any(f.sink_category == "http" for f in flows)
    assert not any(f.vulnerability_id == "FLOW-HTTP" for f in findings)


def test_request_into_url_wrapper_prefers_user_input(tmp_path: Path):
    """A request-sourced caller must not be downgraded to function_param."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "import requests\n"
            "def fetch(url):\n"
            "    requests.get(url)\n"
            "def handler(request):\n"
            "    fetch(request.args['url'])\n"
        ),
    })
    assert any(f.source == "user_input" and f.sink_arg_role == "url" for f in flows)
    http_findings = [f for f in findings if f.vulnerability_id == "FLOW-HTTP"]
    assert http_findings
    assert any(f.confirmed_by_taint for f in http_findings)


def test_constant_url_into_wrapper_has_no_unrelated_findings(tmp_path: Path):
    """A constant passed into a URL wrapper is not SQL/RCE/LLM/body SSRF.

    FLOW-HTTP on the wrapper itself is potential taint (function_param), not
    proof the caller supplied attacker data. The constant call site must not
    create additional sink findings.
    """
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "import requests\n"
            "def fetch(url):\n"
            "    requests.get(url)\n"
            "def handler():\n"
            "    fetch('https://example.com/health')\n"
        ),
    })
    assert not any(f.sink_category in {"sql", "rce", "llm"} for f in flows)
    assert not any(
        f.vulnerability_id in {"FLOW-SQL", "FLOW-RCE", "FLOW-LLM"}
        for f in findings
    )
    assert not any(
        f.sink_category == "http" and f.source == "user_input" for f in flows
    )
    http_findings = [f for f in findings if f.vulnerability_id == "FLOW-HTTP"]
    assert all(f.confidence == "may" for f in http_findings)
    assert all(not f.confirmed_by_taint for f in http_findings)
    assert all(f.function_name == "fetch" for f in http_findings)


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


# ---------------------------------------------------------------------------
# Phase 13 — destination-control precision
# ---------------------------------------------------------------------------

_HOST_ALLOWLIST = (
    "from urllib.parse import urlparse\n"
    "ALLOWED = ('example.com',)\n"
    "def host_permitted(target):\n"
    "    host = urlparse(target).hostname or ''\n"
    "    for allowed in ALLOWED:\n"
    "        if host.endswith(allowed):\n"
    "            return True\n"
    "    return False\n"
)

_ALWAYS_TRUE = (
    "def is_safe_url(target):\n"
    "    return True\n"
)

_PRIVATE_IP_FETCH = (
    "import ipaddress\n"
    "import socket\n"
    "from urllib.parse import urlparse\n"
    "import requests\n"
    "def fetch_checked(url):\n"
    "    host = urlparse(url).hostname or ''\n"
    "    try:\n"
    "        infos = socket.getaddrinfo(host, None)\n"
    "    except socket.gaierror:\n"
    "        raise ValueError('cannot resolve')\n"
    "    for info in infos:\n"
    "        ip = ipaddress.ip_address(info[4][0])\n"
    "        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:\n"
    "            raise ValueError('blocked')\n"
    "    requests.get(url, timeout=15, allow_redirects=False)\n"
)


def test_untrusted_url_without_validation_is_flow_http(tmp_path: Path):
    """A parameter URL with no destination check remains potential FLOW-HTTP."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "import requests\n"
            "def fetch(url):\n"
            "    requests.get(url, allow_redirects=False)\n"
        ),
    })
    assert any(f.sink_category == "http" and f.sink_arg_role == "url" for f in flows)
    http_findings = [f for f in findings if f.vulnerability_id == "FLOW-HTTP"]
    assert http_findings
    assert all(f.confidence == "may" for f in http_findings)
    assert all(not f.confirmed_by_taint for f in http_findings)


def test_effective_host_allowlist_without_redirects_is_not_ssrf(tmp_path: Path):
    """Resolved host allow-list plus disabled redirects prevents FLOW-HTTP."""
    findings, _flows = _promote(tmp_path, {
        "app.py": (
            _HOST_ALLOWLIST
            + "import requests\n"
            "def fetch(url):\n"
            "    if not host_permitted(url):\n"
            "        raise ValueError('host not allowed')\n"
            "    requests.get(url, allow_redirects=False)\n"
        ),
    })
    assert not any(f.vulnerability_id == "FLOW-HTTP" for f in findings)


def test_effective_host_allowlist_with_redirects_still_flow_http(tmp_path: Path):
    """Allow-list of the original URL does not prove the redirected destination."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            _HOST_ALLOWLIST
            + "import requests\n"
            "def fetch(url):\n"
            "    if not host_permitted(url):\n"
            "        raise ValueError('host not allowed')\n"
            "    requests.get(url, allow_redirects=True)\n"
        ),
    })
    assert any(f.sink_category == "http" and f.sink_arg_role == "url" for f in flows)
    assert any(f.vulnerability_id == "FLOW-HTTP" for f in findings)


def test_allowlist_name_without_effective_body_still_flow_http(tmp_path: Path):
    """A validator name alone does not suppress FLOW-HTTP."""
    findings, _flows = _promote(tmp_path, {
        "app.py": (
            _ALWAYS_TRUE
            + "import requests\n"
            "def fetch(url):\n"
            "    if not is_safe_url(url):\n"
            "        raise ValueError('rejected')\n"
            "    requests.get(url, allow_redirects=False)\n"
        ),
    })
    assert any(f.vulnerability_id == "FLOW-HTTP" for f in findings)


def test_unresolved_validator_still_flow_http(tmp_path: Path):
    """An unresolved check is presence of a validator, not a proof."""
    findings, _flows = _promote(tmp_path, {
        "app.py": (
            "import requests\n"
            "from vendor import validate\n"
            "def fetch(url):\n"
            "    if not validate(url):\n"
            "        raise ValueError('rejected')\n"
            "    requests.get(url, allow_redirects=False)\n"
        ),
    })
    assert any(f.vulnerability_id == "FLOW-HTTP" for f in findings)


def test_separate_dns_validation_then_get_url_still_flow_http(tmp_path: Path):
    """getaddrinfo of the host does not bind a later requests.get(url)."""
    findings, flows = _promote(tmp_path, {
        "app.py": _PRIVATE_IP_FETCH,
    })
    assert any(f.sink_category == "http" and f.sink_arg_role == "url" for f in flows)
    http_findings = [f for f in findings if f.vulnerability_id == "FLOW-HTTP"]
    assert http_findings
    assert all(f.confidence == "may" for f in http_findings)
    assert all(not f.confirmed_by_taint for f in http_findings)


def test_private_ip_check_of_other_host_still_flow_http(tmp_path: Path):
    """A private-IP check of a different host does not make ``url`` safe."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "import ipaddress\n"
            "import socket\n"
            "import requests\n"
            "def fetch_checked(url):\n"
            "    infos = socket.getaddrinfo('example.com', None)\n"
            "    for info in infos:\n"
            "        ip = ipaddress.ip_address(info[4][0])\n"
            "        if ip.is_private or ip.is_loopback:\n"
            "            raise ValueError('blocked')\n"
            "    requests.get(url, allow_redirects=False)\n"
        ),
    })
    assert any(f.sink_category == "http" and f.sink_arg_role == "url" for f in flows)
    assert any(f.vulnerability_id == "FLOW-HTTP" for f in findings)


def test_private_ip_block_with_redirects_still_flow_http(tmp_path: Path):
    """Private-IP check of the original host does not survive redirects."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "import ipaddress\n"
            "import socket\n"
            "from urllib.parse import urlparse\n"
            "import requests\n"
            "def fetch_checked(url):\n"
            "    host = urlparse(url).hostname or ''\n"
            "    infos = socket.getaddrinfo(host, None)\n"
            "    for info in infos:\n"
            "        ip = ipaddress.ip_address(info[4][0])\n"
            "        if ip.is_private or ip.is_loopback:\n"
            "            raise ValueError('blocked')\n"
            "    requests.get(url, allow_redirects=True)\n"
        ),
    })
    assert any(f.sink_category == "http" and f.sink_arg_role == "url" for f in flows)
    assert any(f.vulnerability_id == "FLOW-HTTP" for f in findings)


def test_disabled_redirects_alone_still_flow_http(tmp_path: Path):
    """Turning off redirects without a destination check is not enough."""
    findings, _flows = _promote(tmp_path, {
        "app.py": (
            "import requests\n"
            "def fetch(url):\n"
            "    requests.get(url, allow_redirects=False)\n"
        ),
    })
    assert any(f.vulnerability_id == "FLOW-HTTP" for f in findings)


def test_request_sourced_url_remains_flow_http(tmp_path: Path):
    """Existing request→URL taint is unchanged when no destination check exists."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "import requests\n"
            "def handler(request):\n"
            "    url = request.args['url']\n"
            "    requests.get(url)\n"
        ),
    })
    hits = [f for f in _http(flows) if f.source == "user_input"]
    assert hits
    http_findings = [f for f in findings if f.vulnerability_id == "FLOW-HTTP"]
    assert http_findings
    assert any(f.confirmed_by_taint for f in http_findings)


def test_request_sourced_allowlist_without_redirects_is_not_ssrf(tmp_path: Path):
    """Request URL that passes an effective allow-list without redirects is not SSRF."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            _HOST_ALLOWLIST
            + "import requests\n"
            "def handler(request):\n"
            "    url = request.args['url']\n"
            "    if not host_permitted(url):\n"
            "        raise ValueError('host not allowed')\n"
            "    requests.get(url, allow_redirects=False)\n"
        ),
    })
    assert not any(f.sink_category == "http" and f.sink_arg_role == "url" for f in flows)
    assert not any(f.vulnerability_id == "FLOW-HTTP" for f in findings)


def test_cross_file_allowlist_without_redirects_is_not_ssrf(tmp_path: Path):
    """Allow-list body is inspected after import resolution, not by helper name."""
    findings, _flows = _promote(tmp_path, {
        "policy.py": _HOST_ALLOWLIST,
        "app.py": (
            "import requests\n"
            "from policy import host_permitted\n"
            "def fetch(url):\n"
            "    if not host_permitted(url):\n"
            "        raise ValueError('host not allowed')\n"
            "    requests.get(url, allow_redirects=False)\n"
        ),
    })
    assert not any(f.vulnerability_id == "FLOW-HTTP" for f in findings)


def test_function_param_http_still_potential(tmp_path: Path):
    """Unguarded function-parameter URL findings stay potential taint."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "import requests\n"
            "def notify(webhook_url):\n"
            "    requests.post(webhook_url, json={'ok': True})\n"
        ),
    })
    hits = [f for f in _http(flows) if f.sink_arg_role == "url"]
    assert hits
    assert all(f.source == "function_param" for f in hits)
    assert all(f.confidence == "may" for f in hits)
    http_findings = [f for f in findings if f.vulnerability_id == "FLOW-HTTP"]
    assert http_findings
    assert all(f.confidence == "may" for f in http_findings)
    assert all(not f.confirmed_by_taint for f in http_findings)


def test_precision_does_not_change_sql_rce_llm_or_body(tmp_path: Path):
    """Destination-control precision is HTTP-URL only."""
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "import os\n"
            "import requests\n"
            "def search(term):\n"
            "    cursor.execute(f\"SELECT * FROM t WHERE name='{term}'\")\n"
            "def run(cmd):\n"
            "    os.system(cmd)\n"
            "def ask(msg):\n"
            "    requests.post('http://localhost:11434/api/chat', json={'messages': msg})\n"
            "def notify(payload):\n"
            "    requests.post('https://example.com/hooks', json=payload)\n"
            "def handler(request):\n"
            "    body = request.json['message']\n"
            "    q = request.json['q']\n"
            "    cmd = request.json['cmd']\n"
            "    requests.post('https://example.com/hooks', json={'message': body})\n"
            "    cursor.execute(f\"SELECT * FROM t WHERE name='{q}'\")\n"
            "    os.system(cmd)\n"
            "    requests.post('http://localhost:11434/api/chat', json={'messages': body})\n"
        ),
    })
    assert any(f.vulnerability_id in {"FLOW-SQL", "PAT-003"} for f in findings)
    assert any(f.vulnerability_id in {"FLOW-RCE", "PAT-025"} for f in findings)
    assert any(f.vulnerability_id == "FLOW-LLM" for f in findings)
    assert not any(f.vulnerability_id == "FLOW-HTTP" for f in findings)
    assert any(f.sink_category == "sql" and f.source == "user_input" for f in flows)
    assert any(f.sink_category == "rce" and f.source == "user_input" for f in flows)
    assert any(f.sink_category == "llm" and f.source == "user_input" for f in flows)
    body = [f for f in _http(flows) if f.source == "user_input"]
    assert body
    assert all(f.sink_arg_role == "body" for f in body)


def test_httpx_chat_completions_classified_as_llm():
    node = ast.parse(
        'httpx.post(base + "/chat/completions", json={"messages": msgs})'
    ).body[0].value
    tags = classify_sink(node)
    assert "http" in tags
    assert "llm" in tags


def test_httpx_chat_completions_promotes_flow_llm(tmp_path: Path):
    findings, flows = _promote(tmp_path, {
        "app.py": (
            "import httpx\n"
            "def handler(request):\n"
            "    text = request.json['message']\n"
            "    httpx.post(\n"
            "        'https://api.openai.com/v1/chat/completions',\n"
            "        json={'messages': [{'role': 'user', 'content': text}]},\n"
            "    )\n"
        ),
    })
    assert any(f.sink_category == "llm" and f.source == "user_input" for f in flows)
    assert any(f.vulnerability_id == "FLOW-LLM" for f in findings)
    assert not any(f.vulnerability_id == "FLOW-HTTP" for f in findings)


def test_httpx_client_with_local_url_promotes_flow_llm(tmp_path: Path):
    findings, flows = _promote(tmp_path, {
        "llm.py": (
            "import httpx\n"
            "def chat(messages):\n"
            "    payload = {'model': 'x', 'messages': messages}\n"
            "    url = f'{base}/chat/completions'\n"
            "    with httpx.Client() as client:\n"
            "        client.post(url, json=payload)\n"
            "def handler(request):\n"
            "    chat([{'role': 'user', 'content': request.json['message']}])\n"
        ),
    })
    assert any(f.sink_category == "llm" and f.source == "user_input" for f in flows)
    assert any(f.vulnerability_id == "FLOW-LLM" for f in findings)
    assert not any(f.vulnerability_id == "FLOW-HTTP" for f in findings)


def test_user_input_preferred_over_env_at_same_http_llm_sink(tmp_path: Path):
    """Env secrets in the same wrapper must not hide the user→LLM FLOW-LLM row."""
    findings, flows = _promote(tmp_path, {
        "llm.py": (
            "import httpx, os\n"
            "def chat(messages, system=None):\n"
            "    payload = {'model': 'x', 'messages': messages, 'max_tokens': 8}\n"
            "    url = f'{base}/chat/completions'\n"
            "    with httpx.Client() as client:\n"
            "        client.post(url, json=payload, headers={'Authorization': system})\n"
            "def handler(request):\n"
            "    chat(\n"
            "        [{'role': 'user', 'content': request.json['message']}],\n"
            "        system=os.environ['OPENROUTER_API_KEY'],\n"
            "    )\n"
        ),
    })
    assert any(f.sink_category == "llm" and f.source == "user_input" for f in flows)
    llm_findings = [f for f in findings if f.vulnerability_id == "FLOW-LLM"]
    assert llm_findings
    assert any(f.confirmed_by_taint for f in llm_findings)
