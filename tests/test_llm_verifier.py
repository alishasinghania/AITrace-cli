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
    VerificationResult,
    _redact_code,
    _parse_llm_response,
    _select_findings,
    _strip_markdown_fences,
    build_verification_context,
    verify_findings,
)


def _pf(vid, severity="high", confirmed_by_taint=False, dismissed=False, file="app.py", line=5):
    return PatternFinding(
        vulnerability_id=vid, title=f"Finding {vid}", severity=severity,
        confidence="medium", category="", owasp_id="LLM01", cwe="CWE-74",
        file=file, line=line, function_name="handler", pattern_matched="test",
        evidence=["line 5: something"], framework="langchain",
        confirmed_by_taint=confirmed_by_taint, dismissed_as_fp=dismissed,
        cvss_estimate=7.5,
    )


def _empty_taint():
    return CrossFileTaintResult(
        call_graph={}, taint_paths=[], confirmed_pattern_ids=[],
        partial_pattern_ids=[], graph_stats={},
    )


# ---------------------------------------------------------------------------
# Selection logic
# ---------------------------------------------------------------------------

def test_selection_logic_skips_confirmed_findings():
    findings = [
        _pf("PAT-001", confirmed_by_taint=True),
        _pf("PAT-002", confirmed_by_taint=False),
    ]
    selected = _select_findings(findings, max_findings=10)
    assert all(f.vulnerability_id != "PAT-001" for f in selected)
    assert any(f.vulnerability_id == "PAT-002" for f in selected)


def test_selection_logic_skips_low_severity():
    findings = [
        _pf("PAT-001", severity="low"),
        _pf("PAT-002", severity="high"),
    ]
    selected = _select_findings(findings, max_findings=10)
    assert all(f.vulnerability_id != "PAT-001" for f in selected)


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
    "verified": True,
    "final_severity": "critical",
    "confidence": "high",
    "reasoning": "The code has a clear injection path.",
    "attack_scenario": "Attacker sends malicious prompt via /chat endpoint.",
    "attack_payload": "Ignore previous instructions.",
    "remediation": "Sanitize user_query before passing to llm.invoke().",
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


def test_verified_finding_upgrades_severity():
    finding = _pf("PAT-001", severity="high")

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


def test_false_positive_marks_finding_dismissed():
    finding = _pf("PAT-010", severity="high")

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
    assert finding.dismissed_as_fp is True


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
    """When all findings are confirmed/dismissed they should be skipped entirely."""
    findings = [
        _pf("PAT-001", confirmed_by_taint=True),
        _pf("PAT-002", dismissed=True),
        _pf("PAT-003", severity="info"),
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


def test_selection_skips_test_files():
    findings = [
        _pf("PAT-001", file="tests/test_app.py"),
        _pf("PAT-002", file="spec/api_spec.py"),
        _pf("PAT-003", file="src/app.py"),  # real file — should be kept
    ]
    selected = _select_findings(findings, max_findings=10)
    ids = [f.vulnerability_id for f in selected]
    assert "PAT-001" not in ids
    assert "PAT-002" not in ids
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
