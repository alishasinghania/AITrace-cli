"""Unit tests for llm_verifier.py — mocks _call_litellm, no real API calls."""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from core.analyzers.pattern_analyzer import PatternFinding
from core.analyzers.crossfile_taint import CrossFileTaintResult
from core.features.llm_verifier import (
    LLMVerificationResult,
    VERDICT_ERROR,
    VERDICT_FALSE_POSITIVE,
    VERDICT_INCONCLUSIVE,
    VERDICT_VERIFIED,
    VerificationResult,
    _apply_verification,
    _redact_code,
    _parse_llm_response,
    _select_findings,
    _strip_markdown_fences,
    assess_model_payload,
    build_verification_context,
    identity_key,
    overlay_for_finding,
    select_verification_candidates,
    verify_findings,
)


def _pf(
    vid,
    severity="high",
    confirmed_by_taint=False,
    dismissed=False,
    file="app.py",
    line=5,
    function_name="handler",
    evidence=None,
    pattern_matched="test",
):
    return PatternFinding(
        vulnerability_id=vid, title=f"Finding {vid}", severity=severity,
        confidence="medium", category="", owasp_id="LLM01", cwe="CWE-74",
        file=file, line=line, function_name=function_name, pattern_matched=pattern_matched,
        evidence=list(evidence) if evidence is not None else ["line 5: something"],
        framework="langchain",
        confirmed_by_taint=confirmed_by_taint, dismissed_as_fp=dismissed,
        cvss_estimate=7.5,
    )


def _static_snapshot(finding):
    return {
        "severity": finding.severity,
        "confirmed_by_taint": finding.confirmed_by_taint,
        "dismissed_as_fp": finding.dismissed_as_fp,
        "confirmed_by_llm": finding.confirmed_by_llm,
        "llm_reasoning": finding.llm_reasoning,
        "remediation": finding.remediation,
        "cvss_estimate": finding.cvss_estimate,
        "confidence": finding.confidence,
    }


def _empty_taint():
    return CrossFileTaintResult(
        call_graph={}, taint_paths=[], confirmed_pattern_ids=[],
        partial_pattern_ids=[], graph_stats={},
    )


# ---------------------------------------------------------------------------
# Selection logic
# ---------------------------------------------------------------------------

def test_taint_confirmed_flow_rce_and_sql_are_eligible():
    rce = _pf("FLOW-RCE", severity="critical", confirmed_by_taint=True, file="exec.py", line=4)
    sql = _pf("FLOW-SQL", severity="critical", confirmed_by_taint=True, file="db.py", line=9)
    rce.taint_path = ["handler → exec"]
    sql.taint_path = ["handler → execute"]
    pat = _pf("PAT-002", severity="high")
    selected = _select_findings([rce, sql, pat], max_findings=10)
    ids = [f.vulnerability_id for f in selected]
    assert "FLOW-RCE" in ids
    assert "FLOW-SQL" in ids
    assert "PAT-002" in ids


def test_pat_findings_remain_eligible():
    findings = [
        _pf("PAT-001", severity="high"),
        _pf("PAT-012", severity="critical"),
    ]
    selected = _select_findings(findings, max_findings=10)
    ids = [f.vulnerability_id for f in selected]
    assert "PAT-001" in ids
    assert "PAT-012" in ids


def test_low_severity_overflows_when_limit_reached():
    findings = [
        _pf("PAT-001", severity="low"),
        _pf("PAT-002", severity="high"),
    ]
    selected, records = select_verification_candidates(findings, max_findings=1)
    assert [f.vulnerability_id for f in selected] == ["PAT-002"]
    assert any(r.action == "overflow" and r.finding_id == "PAT-001" for r in records)


def test_selection_logic_prioritizes_lethal_trifecta():
    findings = [
        _pf("PAT-001", severity="high"),
        _pf("PAT-012", severity="critical"),
        _pf("PAT-003", severity="critical"),
    ]
    selected = _select_findings(findings, max_findings=10)
    assert selected[0].vulnerability_id == "PAT-012"


def test_selection_logic_skips_dismissed():
    findings = [
        _pf("PAT-001", dismissed=True),
        _pf("PAT-002"),
    ]
    selected = _select_findings(findings, max_findings=10)
    assert all(f.vulnerability_id != "PAT-001" for f in selected)


def test_max_findings_limit_respected():
    findings = [_pf(f"PAT-{i:03d}", severity="high") for i in range(1, 11)]
    selected = _select_findings(findings, max_findings=3)
    assert len(selected) <= 3


# ---------------------------------------------------------------------------
# Privacy redaction
# ---------------------------------------------------------------------------

def test_privacy_redaction_removes_api_keys():
    code = 'api_key = "sk-abcdefghijklmnopqrstuvwxyz123456"'
    redacted = _redact_code(code)
    assert "sk-abcdefghijklmnopqrstuvwxyz123456" not in redacted
    assert "REDACTED" in redacted


def test_privacy_redaction_removes_db_urls():
    code = 'db_url = "postgresql://user:password@db.example.com/mydb"'
    redacted = _redact_code(code)
    assert "user:password" not in redacted
    assert "REDACTED" in redacted


def test_privacy_redaction_removes_aws_keys():
    code = 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"'   # exactly 20 chars (AKIA + 16)
    redacted = _redact_code(code)
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted


def test_privacy_redaction_preserves_logic():
    code = """
def chat(query):
    result = llm.invoke(query)
    return result
"""
    redacted = _redact_code(code)
    assert "def chat" in redacted
    assert "llm.invoke" in redacted


# ---------------------------------------------------------------------------
# JSON parsing
# ---------------------------------------------------------------------------

def test_json_parsing_handles_markdown_fences():
    json_in_fences = """```json
{"verified": true, "final_severity": "critical", "reasoning": "test",
 "confidence": "high", "attack_scenario": "x", "attack_payload": "",
 "remediation": "fix it", "false_positive": false, "false_positive_reason": "",
 "owasp_category": "LLM01", "cvss_estimate": 8.5,
 "exploit_complexity": "low", "requires_authentication": false}
```"""
    parsed = _parse_llm_response(json_in_fences)
    assert parsed is not None
    assert parsed["verified"] is True


def test_json_parsing_handles_clean_json():
    clean = '{"verified": false, "false_positive": true, "reasoning": "no path", "final_severity": "low"}'
    parsed = _parse_llm_response(clean)
    assert parsed is not None
    assert parsed["false_positive"] is True


def test_json_parsing_returns_none_on_garbage():
    parsed = _parse_llm_response("This is not JSON at all!!!")
    assert parsed is None


def test_strip_markdown_fences():
    text = "```\n{\"key\": \"value\"}\n```"
    stripped = _strip_markdown_fences(text)
    assert "```" not in stripped
    assert "key" in stripped


# ---------------------------------------------------------------------------
# build_verification_context — public function
# ---------------------------------------------------------------------------

def test_build_verification_context_returns_dict():
    finding = _pf("PAT-001")
    taint = _empty_taint()

    with tempfile.TemporaryDirectory() as tmpdir:
        rp = Path(tmpdir)
        (rp / "app.py").write_text(
            "import os\n\ndef handler(query):\n    return llm.invoke(query)\n"
        )
        ctx = build_verification_context(rp, finding, taint)

    assert isinstance(ctx, dict)
    assert "primary_function" in ctx
    assert "imports" in ctx
    assert "taint_path_summary" in ctx
    assert "supporting_functions" in ctx


def test_build_verification_context_handles_missing_file():
    finding = _pf("PAT-001", file="nonexistent.py")
    taint = _empty_taint()

    with tempfile.TemporaryDirectory() as tmpdir:
        rp = Path(tmpdir)
        ctx = build_verification_context(rp, finding, taint)

    # Should return empty strings, not raise
    assert ctx["primary_function"] == ""


# ---------------------------------------------------------------------------
# API interaction — mock _call_litellm
# ---------------------------------------------------------------------------

_MOCK_RESPONSE_JSON = json.dumps({
    "verdict": "VERIFIED",
    "verified": True,
    "final_severity": "critical",
    "confidence": "high",
    "reasoning": "handler passes query into llm.invoke in app.py with no sanitizer.",
    "attack_scenario": "Attacker sends a payload to handler which reaches llm.invoke.",
    "attack_payload": "Ignore previous instructions.",
    "remediation": "Sanitize query before passing to llm.invoke().",
    "false_positive": False,
    "false_positive_reason": "",
    "owasp_category": "LLM01 Prompt Injection",
    "cvss_estimate": 8.8,
    "exploit_complexity": "low",
    "requires_authentication": False,
})

_FP_RESPONSE_JSON = json.dumps({
    "verified": False,
    "final_severity": "low",
    "confidence": "high",
    "reasoning": "The variable is loaded from environment, not hardcoded.",
    "attack_scenario": "",
    "attack_payload": "",
    "remediation": "",
    "false_positive": True,
    "false_positive_reason": "Value comes from os.environ.get(), not a hardcoded string.",
    "owasp_category": "LLM09",
    "cvss_estimate": 0.0,
    "exploit_complexity": "high",
    "requires_authentication": True,
})


def _with_mock_litellm():
    """Context manager: patches sys.modules so litellm appears installed."""
    return patch.dict("sys.modules", {"litellm": MagicMock()})


def test_verified_finding_leaves_original_unchanged():
    finding = _pf("PAT-001", severity="high")
    before = _static_snapshot(finding)

    with tempfile.TemporaryDirectory() as tmpdir:
        rp = Path(tmpdir)
        (rp / "app.py").write_text("def handler(q):\n    return llm.invoke(q)\n")

        with _with_mock_litellm(), \
             patch("core.features.llm_verifier._call_litellm",
                   return_value=(_MOCK_RESPONSE_JSON, 700, None)), \
             patch("time.sleep"):
            result = verify_findings(
                repo_root=rp,
                pattern_findings=[finding],
                taint_result=_empty_taint(),
                api_key="sk-test-key-placeholder-abc12345678",
                max_findings_to_verify=5,
            )

    assert isinstance(result, LLMVerificationResult)
    assert result.api_calls_made >= 1
    assert result.findings_verified >= 1
    assert result.verifications[0].verdict == VERDICT_VERIFIED
    assert _static_snapshot(finding) == before
    assert finding.severity == "high"
    assert finding.confirmed_by_llm is False
    assert finding.dismissed_as_fp is False


def test_false_positive_leaves_original_unchanged():
    finding = _pf("PAT-010", severity="high")
    before = _static_snapshot(finding)

    with tempfile.TemporaryDirectory() as tmpdir:
        rp = Path(tmpdir)
        (rp / "app.py").write_text("import os\napi_key = os.environ.get('KEY')\n")

        with _with_mock_litellm(), \
             patch("core.features.llm_verifier._call_litellm",
                   return_value=(_FP_RESPONSE_JSON, 400, None)), \
             patch("time.sleep"):
            result = verify_findings(
                repo_root=rp,
                pattern_findings=[finding],
                taint_result=_empty_taint(),
                api_key="sk-test-key-placeholder-abc12345678",
                max_findings_to_verify=5,
            )

    assert isinstance(result, LLMVerificationResult)
    assert result.findings_dismissed >= 1
    assert result.verifications[0].verdict == VERDICT_FALSE_POSITIVE
    assert finding.dismissed_as_fp is False
    assert _static_snapshot(finding) == before


def test_graceful_handling_of_api_failure():
    finding = _pf("PAT-002", severity="critical")

    with tempfile.TemporaryDirectory() as tmpdir:
        rp = Path(tmpdir)
        (rp / "app.py").write_text("x = 1\n")

        with _with_mock_litellm(), \
             patch("core.features.llm_verifier._call_litellm",
                   return_value=(None, 0, "Connection error")), \
             patch("time.sleep"):
            result = verify_findings(
                repo_root=rp,
                pattern_findings=[finding],
                taint_result=_empty_taint(),
                api_key="sk-test-key-placeholder-abc12345678",
                max_findings_to_verify=5,
            )

    # Should not raise — gracefully handle errors
    assert isinstance(result, LLMVerificationResult)
    assert result.findings_errored >= 1


def test_retry_on_rate_limit():
    finding = _pf("PAT-003", severity="critical")
    call_count = {"n": 0}

    def side_effect(*args, **kwargs):
        call_count["n"] += 1
        if call_count["n"] < 2:
            return (None, 0, "429 Rate limit exceeded")
        return (_MOCK_RESPONSE_JSON, 700, None)

    with tempfile.TemporaryDirectory() as tmpdir:
        rp = Path(tmpdir)
        (rp / "app.py").write_text("def run():\n    cursor.execute(sql)\n")

        with _with_mock_litellm(), \
             patch("core.features.llm_verifier._call_litellm", side_effect=side_effect), \
             patch("time.sleep"):
            result = verify_findings(
                repo_root=rp,
                pattern_findings=[finding],
                taint_result=_empty_taint(),
                api_key="sk-test-key-placeholder-abc12345678",
                max_findings_to_verify=5,
            )

    assert isinstance(result, LLMVerificationResult)
    assert call_count["n"] >= 2


def test_no_litellm_returns_empty_result():
    """When litellm is not installed, returns empty result gracefully."""
    import builtins
    real_import = builtins.__import__

    def mock_import(name, *args, **kwargs):
        if name == "litellm":
            raise ImportError("No module named 'litellm'")
        return real_import(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=mock_import):
        result = verify_findings(
            repo_root=Path("/tmp"),
            pattern_findings=[_pf("PAT-001")],
            taint_result=_empty_taint(),
            api_key="sk-test",
        )
    assert result.findings_skipped >= 1
    assert result.api_calls_made == 0


# ---------------------------------------------------------------------------
# ProviderConfig integration
# ---------------------------------------------------------------------------

def test_verify_findings_uses_provider_config():
    """verify_findings uses model/key from ProviderConfig when provided."""
    from core.features.credentials.resolver import ProviderConfig

    finding = _pf("PAT-001", severity="high")
    pc = ProviderConfig(
        provider="anthropic",
        model="claude-haiku-4-5-20251001",
        api_key="sk-prov-config-test-key",
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        rp = Path(tmpdir)
        (rp / "app.py").write_text("def h(q):\n    llm.invoke(q)\n")

        with _with_mock_litellm(), \
             patch("core.features.llm_verifier._call_litellm",
                   return_value=(_MOCK_RESPONSE_JSON, 700, None)) as mock_call, \
             patch("time.sleep"):
            result = verify_findings(
                repo_root=rp,
                pattern_findings=[finding],
                taint_result=_empty_taint(),
                provider_config=pc,
                max_findings_to_verify=5,
            )

    assert result.model_used == "claude-haiku-4-5-20251001"
    assert result.provider_used == "anthropic"
    # Key must be cleared after call
    assert pc.api_key is None
    # litellm was called with the right model
    call_args = mock_call.call_args
    assert call_args[0][0] == "claude-haiku-4-5-20251001"
    assert call_args[0][1] == "sk-prov-config-test-key"


def test_verification_result_has_new_fields():
    """VerificationResult must have provider, latency_ms fields."""
    vr = VerificationResult(
        finding_id="PAT-001",
        original_severity="high",
        verified=True,
        final_severity="critical",
        confidence="high",
        reasoning="test",
        attack_scenario="",
        attack_payload="",
        remediation="",
        false_positive=False,
        false_positive_reason="",
        owasp_category="LLM01",
        cvss_estimate=8.0,
        exploit_complexity="low",
        requires_authentication=False,
        model_used="claude-haiku-4-5-20251001",
        provider="anthropic",
        tokens_used=500,
        latency_ms=1200,
        verification_time_ms=1200,
    )
    d = vr.to_dict()
    assert "provider" in d
    assert "latency_ms" in d
    assert d["provider"] == "anthropic"
    assert d["latency_ms"] == 1200


def test_llm_verification_result_has_provider_fields():
    """LLMVerificationResult must have provider_used, model_used fields."""
    lr = LLMVerificationResult(
        verifications=[],
        api_calls_made=3,
        findings_verified=2,
        findings_dismissed=0,
        findings_skipped=1,
        findings_errored=0,
        total_tokens_used=2100,
        provider_used="anthropic",
        model_used="claude-haiku-4-5-20251001",
    )
    d = lr.to_dict()
    assert d["provider_used"] == "anthropic"
    assert d["model_used"] == "claude-haiku-4-5-20251001"


# ---------------------------------------------------------------------------
# Edge cases — finding selection
# ---------------------------------------------------------------------------

def test_empty_findings_list_returns_zero_result():
    with tempfile.TemporaryDirectory() as tmpdir:
        with _with_mock_litellm(), patch("time.sleep"):
            result = verify_findings(
                repo_root=Path(tmpdir),
                pattern_findings=[],
                taint_result=_empty_taint(),
                api_key="sk-test",
            )
    assert result.api_calls_made == 0
    assert result.findings_skipped == 0
    assert result.findings_verified == 0


def test_all_findings_pre_filtered_no_api_calls():
    """Statically dismissed findings are skipped and produce no API calls."""
    findings = [
        _pf("PAT-001", dismissed=True),
        _pf("PAT-002", dismissed=True),
        _pf("PAT-003", dismissed=True),
    ]
    with tempfile.TemporaryDirectory() as tmpdir:
        with _with_mock_litellm(), patch("time.sleep"):
            result = verify_findings(
                repo_root=Path(tmpdir),
                pattern_findings=findings,
                taint_result=_empty_taint(),
                api_key="sk-test",
                max_findings_to_verify=10,
            )
    assert result.api_calls_made == 0
    assert result.findings_skipped == 3


def test_max_findings_zero_no_api_calls():
    findings = [_pf("PAT-001", severity="critical")]
    with tempfile.TemporaryDirectory() as tmpdir:
        with _with_mock_litellm(), patch("time.sleep"):
            result = verify_findings(
                repo_root=Path(tmpdir),
                pattern_findings=findings,
                taint_result=_empty_taint(),
                api_key="sk-test",
                max_findings_to_verify=0,
            )
    assert result.api_calls_made == 0


def test_selection_includes_test_files_shown_in_html():
    findings = [
        _pf("PAT-001", file="tests/test_app.py"),
        _pf("PAT-002", file="spec/api_spec.py"),
        _pf("PAT-003", file="src/app.py"),
    ]
    selected = _select_findings(findings, max_findings=10)
    ids = [f.vulnerability_id for f in selected]
    assert "PAT-001" in ids
    assert "PAT-002" in ids
    assert "PAT-003" in ids


# ---------------------------------------------------------------------------
# Edge cases — context gathering
# ---------------------------------------------------------------------------

def test_build_verification_context_with_taint_path():
    """Taint path should appear in the taint_path_summary field."""
    finding = _pf("PAT-001")
    finding.taint_path = ["handler → process_query → llm.invoke"]
    taint = _empty_taint()

    with tempfile.TemporaryDirectory() as tmpdir:
        rp = Path(tmpdir)
        (rp / "app.py").write_text("def handler(q):\n    llm.invoke(q)\n")
        ctx = build_verification_context(rp, finding, taint)

    assert "handler → process_query → llm.invoke" in ctx["taint_path_summary"]


def test_build_verification_context_empty_file():
    """Finding with empty file path should not raise."""
    finding = _pf("PAT-001", file="")
    taint = _empty_taint()

    with tempfile.TemporaryDirectory() as tmpdir:
        ctx = build_verification_context(Path(tmpdir), finding, taint)

    assert ctx["primary_function"] == ""


# ---------------------------------------------------------------------------
# Edge cases — response parsing / error path
# ---------------------------------------------------------------------------

def test_parse_failed_sets_error_field():
    """When LLM returns non-parseable text, error should be 'parse_failed'."""
    finding = _pf("PAT-001", severity="high")

    with tempfile.TemporaryDirectory() as tmpdir:
        rp = Path(tmpdir)
        (rp / "app.py").write_text("def h(q): pass\n")

        call_count = {"n": 0}

        def garbled_response(*args, **kwargs):
            call_count["n"] += 1
            return ("this is not json at all!!!", 100, None)

        with _with_mock_litellm(), \
             patch("core.features.llm_verifier._call_litellm", side_effect=garbled_response), \
             patch("time.sleep"):
            result = verify_findings(
                repo_root=rp,
                pattern_findings=[finding],
                taint_result=_empty_taint(),
                api_key="sk-test",
                max_findings_to_verify=5,
            )

    assert result.findings_errored >= 1
    assert result.verifications[0].error == "parse_failed"


# ---------------------------------------------------------------------------
# Edge cases — local provider (Ollama)
# ---------------------------------------------------------------------------

def test_local_provider_config_no_api_key():
    """Ollama provider_config with no key should still work (key=None is valid for local)."""
    from core.features.credentials.resolver import ProviderConfig

    finding = _pf("PAT-001", severity="high")
    pc = ProviderConfig(provider="ollama", model="ollama/llama3")
    # is_local=True, api_key is None

    with tempfile.TemporaryDirectory() as tmpdir:
        rp = Path(tmpdir)
        (rp / "app.py").write_text("def h(q):\n    llm.invoke(q)\n")

        with _with_mock_litellm(), \
             patch("core.features.llm_verifier._call_litellm",
                   return_value=(_MOCK_RESPONSE_JSON, 700, None)) as mock_call, \
             patch("time.sleep"):
            result = verify_findings(
                repo_root=rp,
                pattern_findings=[finding],
                taint_result=_empty_taint(),
                provider_config=pc,
                max_findings_to_verify=5,
            )

    assert result.api_calls_made >= 1
    # Key passed to litellm must be None for local model
    call_args = mock_call.call_args
    assert call_args[0][1] is None   # api_key positional arg


# ---------------------------------------------------------------------------
# Non-destructive overlay — verdict assessment
# ---------------------------------------------------------------------------

def test_empty_reasoning_is_inconclusive():
    finding = _pf("PAT-001")
    payload = {
        "verified": True,
        "false_positive": False,
        "reasoning": "   ",
        "cvss_estimate": 8.0,
    }
    decision = assess_model_payload(finding, payload, {"primary_function": "def handler(q): llm.invoke(q)"})
    assert decision["verdict"] == VERDICT_INCONCLUSIVE
    assert _static_snapshot(finding) == _static_snapshot(_pf("PAT-001"))


def test_missing_evidence_is_inconclusive():
    finding = _pf(
        "PAT-001",
        file="",
        function_name="",
        evidence=[],
        pattern_matched="",
    )
    payload = {
        "verified": True,
        "false_positive": False,
        "reasoning": "This is definitely exploitable in production.",
        "cvss_estimate": 9.0,
    }
    decision = assess_model_payload(finding, payload, {})
    assert decision["verdict"] == VERDICT_INCONCLUSIVE
    assert decision.get("note") == "missing_evidence"


def test_unsupported_reason_is_inconclusive():
    finding = _pf("PAT-001")
    payload = {
        "verified": True,
        "false_positive": False,
        "reasoning": "This is clearly a vulnerability.",
        "cvss_estimate": 8.0,
    }
    decision = assess_model_payload(
        finding, payload, {"primary_function": "def handler(q):\n    return llm.invoke(q)\n"}
    )
    assert decision["verdict"] == VERDICT_INCONCLUSIVE


def test_conflicting_flags_are_error():
    finding = _pf("PAT-001")
    payload = {
        "verified": True,
        "false_positive": True,
        "reasoning": "handler is both verified and a false positive",
        "cvss_estimate": 5.0,
    }
    decision = assess_model_payload(finding, payload)
    assert decision["verdict"] == VERDICT_ERROR
    assert decision["error"] == "contradictory_verdict"


def test_invalid_cvss_is_error():
    finding = _pf("PAT-001")
    payload = {
        "verified": True,
        "false_positive": False,
        "reasoning": "handler reaches llm.invoke",
        "cvss_estimate": "high",
    }
    decision = assess_model_payload(finding, payload, {"primary_function": "def handler(q): llm.invoke(q)"})
    assert decision["verdict"] == VERDICT_ERROR
    assert decision["error"] == "invalid_cvss"

    payload["cvss_estimate"] = 99
    decision = assess_model_payload(finding, payload, {"primary_function": "def handler(q): llm.invoke(q)"})
    assert decision["verdict"] == VERDICT_ERROR
    assert decision["error"] == "invalid_cvss"


def test_malformed_json_is_error_without_mutating_finding():
    finding = _pf("PAT-001", severity="high")
    before = _static_snapshot(finding)
    decision = assess_model_payload(finding, None)
    assert decision["verdict"] == VERDICT_ERROR
    assert decision["error"] == "malformed_response"
    assert _static_snapshot(finding) == before


def test_apply_verification_is_noop():
    finding = _pf("PAT-002", severity="critical")
    before = _static_snapshot(finding)
    result = VerificationResult(
        finding_id="PAT-002",
        original_severity="critical",
        verified=True,
        final_severity="low",
        confidence="high",
        reasoning="handler is exploitable",
        attack_scenario="",
        attack_payload="",
        remediation="delete it",
        false_positive=True,
        false_positive_reason="n/a",
        owasp_category="LLM01",
        cvss_estimate=9.9,
        exploit_complexity="low",
        requires_authentication=False,
        model_used="mock",
        provider="mock",
        tokens_used=1,
        latency_ms=1,
        verification_time_ms=1,
        verdict=VERDICT_VERIFIED,
    )
    _apply_verification(finding, result)
    assert _static_snapshot(finding) == before


def test_llm_review_never_suppresses_taint_confirmed_finding():
    taint_hit = _pf("FLOW-RCE", severity="critical", confirmed_by_taint=True)
    taint_hit.taint_path = ["handler → exec"]
    other = _pf("PAT-002", severity="high", file="other.py", line=8)
    before_taint = _static_snapshot(taint_hit)
    fp_json = json.dumps({
        "verified": False,
        "false_positive": True,
        "reasoning": "handler only execs a constant in tests.",
        "false_positive_reason": "handler calls exec on a literal, not q.",
        "final_severity": "low",
        "cvss_estimate": 0.0,
    })

    with tempfile.TemporaryDirectory() as tmpdir:
        rp = Path(tmpdir)
        (rp / "app.py").write_text("def handler(q):\n    exec(q)\n")
        (rp / "other.py").write_text("def handler(q):\n    exec(q)\n")
        with _with_mock_litellm(), \
             patch("core.features.llm_verifier._call_litellm",
                   return_value=(fp_json, 400, None)), \
             patch("time.sleep"):
            result = verify_findings(
                repo_root=rp,
                pattern_findings=[taint_hit, other],
                taint_result=_empty_taint(),
                api_key="sk-test",
                max_findings_to_verify=10,
            )

    assert taint_hit.confirmed_by_taint is True
    assert taint_hit.dismissed_as_fp is False
    assert _static_snapshot(taint_hit) == before_taint
    overlay = overlay_for_finding(result, taint_hit)
    assert overlay is not None
    assert overlay.verdict == VERDICT_FALSE_POSITIVE
    assert taint_hit.severity == "critical"


def test_risk_score_unchanged_by_verification():
    from core.governance.risk_scoring import compute_risk_score
    from core.models import AIBOM
    from types import SimpleNamespace

    finding = _pf("PAT-002", severity="critical")
    aibom = AIBOM(repo_path=Path("."))
    pattern_analysis = SimpleNamespace(findings=[finding])
    before = compute_risk_score(aibom, [], None, None, pattern_analysis=pattern_analysis)

    with tempfile.TemporaryDirectory() as tmpdir:
        rp = Path(tmpdir)
        (rp / "app.py").write_text("def handler(q):\n    exec(q)\n")
        with _with_mock_litellm(), \
             patch("core.features.llm_verifier._call_litellm",
                   return_value=(_FP_RESPONSE_JSON, 400, None)), \
             patch("time.sleep"):
            verify_findings(
                repo_root=rp,
                pattern_findings=[finding],
                taint_result=_empty_taint(),
                api_key="sk-test",
            )

    after = compute_risk_score(aibom, [], None, None, pattern_analysis=pattern_analysis)
    assert after.total_score == before.total_score
    assert finding.dismissed_as_fp is False
    assert finding.severity == "critical"


def test_exploit_eligibility_unchanged_by_verification():
    from core.features.exploit_synthesizer import synthesize
    from types import SimpleNamespace

    finding = _pf("PAT-003", severity="critical", evidence=["Parameter 'query' interpolated into SQL execute()"])
    result_obj = SimpleNamespace(
        dataflow_analysis=None,
        sensitive_exposures=None,
        architecture_result=None,
        prompt_injection_risks=None,
        pattern_analysis=SimpleNamespace(findings=[finding]),
    )
    before = synthesize(result_obj)

    with tempfile.TemporaryDirectory() as tmpdir:
        rp = Path(tmpdir)
        (rp / "app.py").write_text("def handler(q):\n    cursor.execute(q)\n")
        with _with_mock_litellm(), \
             patch("core.features.llm_verifier._call_litellm",
                   return_value=(_FP_RESPONSE_JSON, 400, None)), \
             patch("time.sleep"):
            verify_findings(
                repo_root=rp,
                pattern_findings=[finding],
                taint_result=_empty_taint(),
                api_key="sk-test",
            )

    after = synthesize(result_obj)
    assert len(after) == len(before)
    assert finding.dismissed_as_fp is False


def test_empty_reasoning_verify_findings_path():
    finding = _pf("PAT-001")
    payload = json.dumps({
        "verified": True,
        "false_positive": False,
        "reasoning": "",
        "final_severity": "critical",
        "cvss_estimate": 9.1,
    })
    with tempfile.TemporaryDirectory() as tmpdir:
        rp = Path(tmpdir)
        (rp / "app.py").write_text("def handler(q):\n    return llm.invoke(q)\n")
        with _with_mock_litellm(), \
             patch("core.features.llm_verifier._call_litellm", return_value=(payload, 10, None)), \
             patch("time.sleep"):
            result = verify_findings(
                repo_root=rp,
                pattern_findings=[finding],
                taint_result=_empty_taint(),
                api_key="sk-test",
            )
    assert result.verifications[0].verdict == VERDICT_INCONCLUSIVE
    assert result.findings_inconclusive >= 1
    assert finding.severity == "high"
    assert finding.confirmed_by_llm is False


def test_conflicting_flags_verify_findings_path():
    finding = _pf("PAT-001")
    payload = json.dumps({
        "verified": True,
        "false_positive": True,
        "reasoning": "handler is both things",
        "cvss_estimate": 4.0,
    })
    with tempfile.TemporaryDirectory() as tmpdir:
        rp = Path(tmpdir)
        (rp / "app.py").write_text("def handler(q):\n    return llm.invoke(q)\n")
        with _with_mock_litellm(), \
             patch("core.features.llm_verifier._call_litellm", return_value=(payload, 10, None)), \
             patch("time.sleep"):
            result = verify_findings(
                repo_root=rp,
                pattern_findings=[finding],
                taint_result=_empty_taint(),
                api_key="sk-test",
            )
    assert result.verifications[0].verdict == VERDICT_ERROR
    assert result.findings_errored >= 1
    assert finding.dismissed_as_fp is False
    assert finding.severity == "high"


def test_invalid_cvss_verify_findings_path():
    finding = _pf("PAT-001")
    payload = json.dumps({
        "verified": True,
        "false_positive": False,
        "reasoning": "handler reaches llm.invoke",
        "cvss_estimate": "n/a",
    })
    with tempfile.TemporaryDirectory() as tmpdir:
        rp = Path(tmpdir)
        (rp / "app.py").write_text("def handler(q):\n    return llm.invoke(q)\n")
        with _with_mock_litellm(), \
             patch("core.features.llm_verifier._call_litellm", return_value=(payload, 10, None)), \
             patch("time.sleep"):
            result = verify_findings(
                repo_root=rp,
                pattern_findings=[finding],
                taint_result=_empty_taint(),
                api_key="sk-test",
            )
    assert result.verifications[0].verdict == VERDICT_ERROR
    assert result.verifications[0].error == "invalid_cvss"
    assert finding.severity == "high"


def test_engine_records_verifier_exception(tmp_path):
    from core.engine import AITraceEngine

    (tmp_path / "app.py").write_text("x = 1\n")
    engine = AITraceEngine(tmp_path)
    engine.verify_with_llm = True
    with patch("core.features.llm_verifier.verify_findings", side_effect=RuntimeError("boom")):
        result = engine.analyze()
    assert result.llm_verification is not None
    assert result.llm_verification.errors
    assert "boom" in result.llm_verification.errors[0]
    assert result.llm_verification.findings_errored >= 1


def test_no_litellm_records_error():
    import builtins
    real_import = builtins.__import__

    def mock_import(name, *args, **kwargs):
        if name == "litellm":
            raise ImportError("No module named 'litellm'")
        return real_import(name, *args, **kwargs)

    finding = _pf("PAT-001")
    with patch("builtins.__import__", side_effect=mock_import):
        result = verify_findings(
            repo_root=Path("/tmp"),
            pattern_findings=[finding],
            taint_result=_empty_taint(),
            api_key="sk-test",
        )
    assert result.api_calls_made == 0
    assert "litellm_not_installed" in result.errors
    assert finding.dismissed_as_fp is False


def test_overlay_for_finding_matches_file_and_line():
    finding = _pf("PAT-002", file="a.py", line=10)
    other = _pf("PAT-002", file="b.py", line=20)
    overlay = VerificationResult(
        finding_id="PAT-002",
        original_severity="high",
        verified=True,
        final_severity="high",
        confidence="high",
        reasoning="handler in a.py",
        attack_scenario="",
        attack_payload="",
        remediation="",
        false_positive=False,
        false_positive_reason="",
        owasp_category="LLM01",
        cvss_estimate=7.5,
        exploit_complexity="low",
        requires_authentication=False,
        model_used="mock",
        provider="mock",
        tokens_used=1,
        latency_ms=1,
        verification_time_ms=1,
        verdict=VERDICT_VERIFIED,
        finding_file="a.py",
        finding_line=10,
    )
    bundle = LLMVerificationResult(
        verifications=[overlay],
        api_calls_made=1,
        findings_verified=1,
        findings_dismissed=0,
        findings_skipped=0,
        findings_errored=0,
        total_tokens_used=1,
    )
    assert overlay_for_finding(bundle, finding) is overlay
    assert overlay_for_finding(bundle, other) is None


def test_duplicate_identity_reviewed_once():
    first = _pf("FLOW-RCE", confirmed_by_taint=True, file="app.py", line=8)
    dup = _pf("FLOW-RCE", confirmed_by_taint=True, file="app.py", line=8)
    first.taint_path = ["handler → exec"]
    dup.taint_path = ["handler → exec"]
    selected, records = select_verification_candidates([first, dup], max_findings=10)
    assert len(selected) == 1
    assert any(r.action == "duplicate" and r.reason == "duplicate_identity" for r in records)


def test_overflow_is_recorded_not_silently_discarded():
    findings = [
        _pf(f"PAT-{i:03d}", severity="high", file=f"mod{i}.py", line=i)
        for i in range(1, 13)
    ]
    selected, records = select_verification_candidates(findings, max_findings=10)
    assert len(selected) == 10
    overflow = [r for r in records if r.action == "overflow"]
    assert len(overflow) == 2
    assert all(r.reason == "review_limit" for r in overflow)
    overflow_ids = {r.identity_key for r in overflow}
    selected_ids = {identity_key(f) for f in selected}
    assert overflow_ids.isdisjoint(selected_ids)


def test_selection_order_is_deterministic():
    findings = [
        _pf("PAT-001", severity="medium", file="b.py", line=2),
        _pf("FLOW-RCE", severity="critical", confirmed_by_taint=True, file="a.py", line=1),
        _pf("PAT-002", severity="high", file="c.py", line=3),
    ]
    findings[1].taint_path = ["src → exec"]
    first, _ = select_verification_candidates(list(reversed(findings)), 10)
    second, _ = select_verification_candidates(findings, 10)
    assert [identity_key(f) for f in first] == [identity_key(f) for f in second]
    assert first[0].vulnerability_id == "FLOW-RCE"


def test_identity_matches_html_security_finding():
    from core.exporters.finding_contract import identity_key as contract_key, serialize_finding
    from core.models import Evidence, Finding, FindingCategory, Severity

    pf = _pf("FLOW-SQL", severity="critical", confirmed_by_taint=True, file="db.py", line=12)
    pf.taint_path = ["query → execute"]
    finding = Finding(
        id=pf.vulnerability_id,
        title=pf.title,
        category=FindingCategory.TAINT_CONFIRMED,
        severity=Severity.CRITICAL,
        description="sql",
        evidence=[Evidence(description=pf.evidence[0], file=pf.file, line=pf.line)],
        metadata={"sink_file": pf.file, "sink_line": pf.line, "confirmed_by_taint": True},
    )
    assert identity_key(pf) == contract_key(finding)
    ser = serialize_finding(finding)
    assert ser["id"] == pf.vulnerability_id
    assert ser["sink_file"] == pf.file
    assert ser["sink_line"] == pf.line
    selected, _ = select_verification_candidates([finding], 10)
    assert selected[0] is finding


def test_false_positive_overlay_does_not_set_static_dismissal():
    finding = _pf("FLOW-RCE", severity="critical", confirmed_by_taint=True)
    finding.taint_path = ["handler → exec"]
    fp_json = json.dumps({
        "verified": False,
        "false_positive": True,
        "reasoning": "handler exec is behind an allowlist.",
        "false_positive_reason": "handler sanitizes q before exec.",
        "cvss_estimate": 0.0,
    })
    with tempfile.TemporaryDirectory() as tmpdir:
        rp = Path(tmpdir)
        (rp / "app.py").write_text("def handler(q):\n    exec(q)\n")
        with _with_mock_litellm(), \
             patch("core.features.llm_verifier._call_litellm", return_value=(fp_json, 10, None)), \
             patch("time.sleep"):
            result = verify_findings(
                repo_root=rp,
                pattern_findings=[finding],
                taint_result=_empty_taint(),
                api_key="sk-test",
            )
    assert result.verifications[0].verdict == VERDICT_FALSE_POSITIVE
    assert finding.dismissed_as_fp is False
    assert finding.confirmed_by_taint is True
    assert finding.severity == "critical"


def test_verify_findings_records_overflow_in_result():
    findings = [
        _pf(f"PAT-{i:03d}", severity="high", file=f"m{i}.py", line=i)
        for i in range(1, 5)
    ]
    with tempfile.TemporaryDirectory() as tmpdir:
        rp = Path(tmpdir)
        for i in range(1, 5):
            (rp / f"m{i}.py").write_text("def handler(q):\n    return q\n")
        with _with_mock_litellm(), \
             patch("core.features.llm_verifier._call_litellm",
                   return_value=(_MOCK_RESPONSE_JSON, 10, None)), \
             patch("time.sleep"):
            result = verify_findings(
                repo_root=rp,
                pattern_findings=findings,
                taint_result=_empty_taint(),
                api_key="sk-test",
                max_findings_to_verify=2,
            )
    actions = {r["action"] for r in result.selection_records}
    assert "selected" in actions
    assert "overflow" in actions
    assert result.findings_skipped >= 2
