"""Phase 4: finding contract, evidence, titles, and coverage metadata."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from core.analyzers.crossfile_taint import analyze_crossfile_taint
from core.analyzers.dataflow_analyzer import DataFlow, analyze_dataflows
from core.analyzers.pattern_analyzer import PatternFinding, analyze_patterns
from core.analyzers.prompt_injection_detector import analyze_prompt_injection
from core.analyzers.taint_catalog import FLOW_META
from core.engine import AITraceEngine
from core.exporters.finding_contract import (
    coverage_from_analysis,
    filter_security_findings,
    serialize_finding,
    summary_counts,
)
from core.exporters.html_report import _plain_title, to_html_report
from core.exporters.risk_report import (
    to_findings_json,
    to_risk_report_json,
    to_risk_report_markdown,
)
from core.models import (
    AIBOM,
    Evidence,
    Finding,
    FindingCategory,
    Severity,
)


def _write_mixed_sinks(root: Path) -> None:
    """Synthetic app with LLM, HTTP URL, HTTP body, SQL, RCE, unresolved call."""
    (root / "app.py").write_text(
        "from flask import request\n"
        "import os\n"
        "import sqlite3\n"
        "import requests\n"
        "\n"
        "def chat():\n"
        "    msg = request.json['message']\n"
        "    llm.invoke(msg)\n"
        "    requests.get(msg)\n"
        "    requests.post('https://api.example/x', json=msg)\n"
        "    conn = sqlite3.connect(':memory:')\n"
        "    cur = conn.cursor()\n"
        "    cur.execute(\"SELECT * FROM t WHERE x = '%s'\" % msg)\n"
        "    os.system('echo ' + msg)\n"
        "    vendor_sdk.complete(msg)\n",
        encoding="utf-8",
    )


def _engine_result(root: Path):
    return AITraceEngine(root).analyze()


def test_flow_llm_identity_consistent_across_outputs(tmp_path: Path):
    _write_mixed_sinks(tmp_path)
    result = _engine_result(tmp_path)
    llm = [f for f in result.findings if f.id == "FLOW-LLM"]
    assert llm, "expected FLOW-LLM finding"
    finding = llm[0]
    expected_title = FLOW_META["llm"][1]
    assert finding.title == expected_title
    assert finding.severity == Severity.HIGH
    assert finding.metadata.get("confidence") in ("high", "may")
    ser = serialize_finding(finding)
    assert ser["id"] == "FLOW-LLM"
    assert ser["title"] == expected_title
    assert ser["severity"] == "high"
    assert ser["confidence"] == finding.metadata.get("confidence")
    html = to_html_report(result, tmp_path)
    assert expected_title in html or _plain_title(finding) == expected_title
    assert "prompt injection vulnerability" not in (finding.title or "").lower()
    md = to_risk_report_markdown(
        result.aibom, result.policy_report, result.findings,
        pattern_analysis=result.pattern_analysis,
    )
    assert "FLOW-LLM" in md
    assert expected_title in md
    report = to_risk_report_json(
        result.aibom, result.policy_report, result.findings,
        dataflow_analysis=result.dataflow_analysis,
        pattern_analysis=result.pattern_analysis,
    )
    row = next(f for f in report["findings"] if f["id"] == "FLOW-LLM")
    assert row["title"] == expected_title
    assert row["severity"] == "high"
    assert row["confidence"] == finding.metadata.get("confidence")


def test_flow_http_url_keeps_role_and_ssrf_semantics(tmp_path: Path):
    _write_mixed_sinks(tmp_path)
    result = _engine_result(tmp_path)
    http_findings = [f for f in result.findings if f.id == "FLOW-HTTP"]
    assert http_findings
    finding = http_findings[0]
    assert finding.metadata.get("sink_arg_role") == "url"
    assert "destination" in finding.title.lower() or "CWE-918" in (finding.tags or [])
    assert "CWE-918" in (finding.tags or [])
    ser = serialize_finding(finding)
    assert ser["sink_arg_role"] == "url"
    html = to_html_report(result, tmp_path)
    assert _plain_title(finding) == FLOW_META["http"][1]
    assert FLOW_META["http"][1] in html


def test_tainted_http_body_is_not_ssrf(tmp_path: Path):
    _write_mixed_sinks(tmp_path)
    flows = analyze_dataflows(tmp_path).data_flows
    body = [
        df for df in flows
        if getattr(df, "sink_category", "") == "http"
        and getattr(df, "sink_arg_role", "") == "body"
    ]
    assert body, "expected an HTTP body DataFlow"
    result = _engine_result(tmp_path)
    for f in result.findings:
        if f.id == "FLOW-HTTP":
            assert f.metadata.get("sink_arg_role") == "url"
    for df in body:
        assert df.sink_arg_role != "url"


def test_sql_and_rce_not_reclassified_as_prompt_injection(tmp_path: Path):
    _write_mixed_sinks(tmp_path)
    result = _engine_result(tmp_path)
    ids = {f.id for f in result.findings}
    assert "FLOW-SQL" in ids
    assert "FLOW-RCE" in ids
    pi = analyze_prompt_injection(tmp_path, dataflow_analysis=result.dataflow_analysis)
    for risk in pi.prompt_injection_risks:
        ev = (risk.evidence or "").lower()
        assert "os.system" not in ev
        assert "cursor.execute" not in ev


def test_separate_sinks_remain_separate_findings(tmp_path: Path):
    _write_mixed_sinks(tmp_path)
    result = _engine_result(tmp_path)
    keys = [
        (f.id, serialize_finding(f)["sink_file"], serialize_finding(f)["sink_line"])
        for f in result.findings
        if str(f.id).startswith("FLOW-")
    ]
    assert len(keys) == len(set(keys))
    assert {k[0] for k in keys} >= {"FLOW-LLM", "FLOW-HTTP", "FLOW-SQL", "FLOW-RCE"}


def test_multiple_evidence_paths_count_as_one_finding(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "def chat():\n"
        "    a = request.json['a']\n"
        "    b = request.args['b']\n"
        "    llm.invoke(a + b)\n",
        encoding="utf-8",
    )
    result = _engine_result(tmp_path)
    llm = [f for f in result.findings if f.id == "FLOW-LLM"]
    assert len(llm) == 1
    counts = summary_counts(result.findings)
    assert counts["finding_count"] == len(result.findings)


def test_source_line_survives_serialization_and_finding(tmp_path: Path):
    _write_mixed_sinks(tmp_path)
    analysis = analyze_dataflows(tmp_path)
    llm_flows = [df for df in analysis.data_flows if df.sink_category == "llm"]
    assert llm_flows
    dumped = llm_flows[0].to_dict()
    assert "source_line" in dumped
    assert dumped["source_line"] is not None
    assert dumped["source_line"] == llm_flows[0].source_line
    result = _engine_result(tmp_path)
    finding = next(f for f in result.findings if f.id == "FLOW-LLM")
    assert finding.metadata.get("source_line") == llm_flows[0].source_line
    row = serialize_finding(finding)
    assert row["source_line"] == llm_flows[0].source_line
    report = to_risk_report_json(
        result.aibom, None, result.findings,
        dataflow_analysis=result.dataflow_analysis,
    )
    json_flow = next(
        f for f in report["taint_data_flows"] if f.get("sink_category") == "llm"
    )
    assert json_flow["source_line"] == llm_flows[0].source_line


def test_missing_evidence_is_not_fabricated():
    df = DataFlow(
        source="user_input",
        sink="llm.invoke",
        file="app.py",
        line=4,
        risk="high",
        source_line=None,
        source_file="",
        sink_category="llm",
    )
    dumped = df.to_dict()
    assert dumped["source_line"] is None
    finding = Finding(
        id="FLOW-LLM",
        title=FLOW_META["llm"][1],
        category=FindingCategory.TAINT_CONFIRMED,
        severity=Severity.HIGH,
        description="llm",
        evidence=[Evidence(description="sink", file="app.py", line=4)],
        metadata={"source_line": None, "source_file": "", "confidence": "high"},
    )
    ser = serialize_finding(finding)
    assert ser["source_line"] is None
    assert ser["line"] == 4
    assert ser["source_line"] != ser["line"]


def test_json_summary_matches_serialized_findings():
    findings = [
        Finding(
            id="FLOW-LLM",
            title="Untrusted input reaches an LLM prompt",
            category=FindingCategory.TAINT_CONFIRMED,
            severity=Severity.HIGH,
            description="llm",
            evidence=[Evidence(description="x", file="a.py", line=1)],
        ),
        Finding(
            id="SEM-1",
            title="MCP poisoned tool description: filesystem",
            category=FindingCategory.SEMANTIC,
            severity=Severity.INFO,
            description="semantic",
        ),
        Finding(
            id="DEP-1",
            title="openai dependency discovered",
            category=FindingCategory.SURFACE,
            severity=Severity.INFO,
            description="inventory",
        ),
    ]
    report = to_risk_report_json(AIBOM(repo_path=Path(".")), None, findings)
    counts = summary_counts(findings)
    assert report["summary"]["finding_count"] == counts["finding_count"] == 3
    assert report["summary"]["security_finding_count"] == counts["security_finding_count"] == 2
    assert len(report["findings"]) == 3
    ids = {f["id"] for f in report["findings"]}
    assert ids == {"FLOW-LLM", "SEM-1", "DEP-1"}
    inv = next(f for f in report["findings"] if f["id"] == "DEP-1")
    assert inv["scope"] == "inventory"
    fj = to_findings_json(findings)
    assert {f["id"] for f in fj["findings"]} == ids


def test_cli_html_markdown_json_share_canonical_set(tmp_path: Path):
    _write_mixed_sinks(tmp_path)
    result = _engine_result(tmp_path)
    canonical = {
        (f.id, serialize_finding(f)["file"], serialize_finding(f)["line"])
        for f in result.findings
    }
    security = {
        (f.id, serialize_finding(f)["file"], serialize_finding(f)["line"])
        for f in filter_security_findings(result.findings)
    }
    report = to_risk_report_json(
        result.aibom, result.policy_report, result.findings,
        dataflow_analysis=result.dataflow_analysis,
        pattern_analysis=result.pattern_analysis,
    )
    json_ids = {(f["id"], f.get("file"), f.get("line")) for f in report["findings"]}
    assert json_ids == canonical
    html = to_html_report(result, tmp_path)
    assert "Security findings" in html
    md = to_risk_report_markdown(
        result.aibom, result.policy_report, result.findings,
        pattern_analysis=result.pattern_analysis,
        dataflow_analysis=result.dataflow_analysis,
    )
    for vid in ("FLOW-LLM", "FLOW-HTTP", "FLOW-SQL", "FLOW-RCE"):
        assert vid in md
    assert security <= canonical


def test_unresolved_calls_in_coverage_metadata(tmp_path: Path):
    _write_mixed_sinks(tmp_path)
    analysis = analyze_dataflows(tmp_path)
    cov = coverage_from_analysis(analysis)
    assert cov["unresolved_calls"]["count"] >= 1
    samples = cov["unresolved_calls"]["samples"]
    assert samples
    assert any("complete" in str(s.get("callee", "")) for s in samples)
    assert analysis.incomplete is False
    report = to_risk_report_json(
        AIBOM(repo_path=tmp_path), None, [],
        dataflow_analysis=analysis,
    )
    assert report["analysis_coverage"]["unresolved_calls"]["count"] >= 1
    assert report["summary"]["taint_analysis_incomplete"] is False
    html = to_html_report(
        SimpleNamespace(
            aibom=AIBOM(
                repo_path=tmp_path,
                components=[],
                models=[],
                dataflows=[],
                mcp_servers=[],
            ),
            findings=[],
            architecture_result=None,
            dataflow_analysis=analysis,
            policy_report=None,
            sensitive_exposures=None,
            model_supply_chain=None,
            prompt_injection_risks=None,
            llm_usage=None,
            repo_type="application",
            architecture_graph=None,
            attack_path_findings=None,
            pattern_analysis=None,
            crossfile_taint=None,
            llm_verification=None,
        ),
        tmp_path,
    )
    assert "unresolved" in html.lower()


def test_structural_reachability_is_not_value_taint(tmp_path: Path):
    (tmp_path / "wrap.py").write_text(
        "def wrapper(x):\n"
        "    return unknown(x)\n"
        "\n"
        "def chat():\n"
        "    from flask import request\n"
        "    msg = request.json['message']\n"
        "    y = wrapper(msg)\n"
        "    llm.invoke(y)\n",
        encoding="utf-8",
    )
    analysis = analyze_dataflows(tmp_path)
    llm = [df for df in analysis.data_flows if df.sink_category == "llm"]
    confirmed_payload = [
        df for df in llm if df.taint_kind == "payload"
    ]
    for df in confirmed_payload:
        joined = " ".join(df.hops)
        assert "unknown" not in joined
    analyze_patterns(tmp_path)
    pats = analyze_patterns(tmp_path)
    analyze_crossfile_taint(tmp_path, list(pats.findings), data_flows=analysis.data_flows)
    flow_llm = [f for f in pats.findings if f.vulnerability_id == "FLOW-LLM"]
    for f in flow_llm:
        assert f.taint_kind == "payload"


def test_dataflow_round_trip_preserves_role_and_kind():
    df = DataFlow(
        source="user_input",
        sink="requests.get",
        file="app.py",
        line=9,
        risk="high",
        source_line=7,
        source_file="app.py",
        sink_category="http",
        taint_kind="payload",
        sink_arg_role="url",
        hops=["app.py::chat:7 source user_input"],
        confidence="high",
    )
    dumped = df.to_dict()
    assert dumped["source_line"] == 7
    assert dumped["taint_kind"] == "payload"
    assert dumped["sink_arg_role"] == "url"
    loaded = json.loads(json.dumps(dumped))
    assert loaded["source_line"] == 7
    pf = PatternFinding(
        vulnerability_id="FLOW-HTTP",
        title=FLOW_META["http"][1],
        severity="high",
        confidence="high",
        category="LLM08 Excessive Agency",
        owasp_id="LLM08",
        cwe="CWE-918",
        file="app.py",
        line=9,
        function_name="chat",
        pattern_matched="value taint to http sink",
        evidence=["x"],
        framework="taint",
        confirmed_by_taint=True,
        taint_kind="payload",
        source_file="app.py",
        source_line=7,
        sink_arg_role="url",
    )
    assert pf.to_dict()["source_line"] == 7
    assert pf.to_dict()["sink_arg_role"] == "url"
