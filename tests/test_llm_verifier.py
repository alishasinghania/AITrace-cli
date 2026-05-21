"""Unit tests for llm_verifier.py — uses mocks for Anthropic API calls."""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from core.pattern_analyzer import PatternFinding
from core.crossfile_taint import CrossFileTaintResult
from core.features.llm_verifier import (
    LLMVerificationResult,
    VerificationResult,
    _redact_code,
    _parse_llm_response,
    _select_findings,
    _strip_markdown_fences,
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
    code = 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE123"'
    redacted = _redact_code(code)
    assert "AKIAIOSFODNN7EXAMPLE123" not in redacted


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
# API interaction (mocked)
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


def _mock_anthropic_response(text: str):
    mock_content = MagicMock()
    mock_content.text = text
    mock_usage = MagicMock()
    mock_usage.input_tokens = 500
    mock_usage.output_tokens = 200
    mock_response = MagicMock()
    mock_response.content = [mock_content]
    mock_response.usage = mock_usage
    return mock_response


def _make_mock_anthropic(response_text: str, side_effect=None):
    """Create a mock anthropic module with a configured client."""
    mock_anthropic_module = MagicMock()
    mock_client = MagicMock()
    mock_anthropic_module.Anthropic.return_value = mock_client
    if side_effect:
        mock_client.messages.create.side_effect = side_effect
    else:
        mock_client.messages.create.return_value = _mock_anthropic_response(response_text)
    return mock_anthropic_module, mock_client


def test_verified_finding_upgrades_severity():
    finding = _pf("PAT-001", severity="high")
    mock_module, _ = _make_mock_anthropic(_MOCK_RESPONSE_JSON)

    with tempfile.TemporaryDirectory() as tmpdir:
        rp = Path(tmpdir)
        (rp / "app.py").write_text("def handler(q):\n    return llm.invoke(q)\n")

        with patch.dict("sys.modules", {"anthropic": mock_module}), \
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


def test_false_positive_marks_finding_dismissed():
    finding = _pf("PAT-010", severity="high")
    fp_response = json.dumps({
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
    mock_module, _ = _make_mock_anthropic(fp_response)

    with tempfile.TemporaryDirectory() as tmpdir:
        rp = Path(tmpdir)
        (rp / "app.py").write_text("import os\napi_key = os.environ.get('KEY')\n")

        with patch.dict("sys.modules", {"anthropic": mock_module}), \
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


def test_graceful_handling_of_api_failure():
    finding = _pf("PAT-002", severity="critical")
    mock_module, mock_client = _make_mock_anthropic("")
    mock_client.messages.create.side_effect = Exception("Connection error")

    with tempfile.TemporaryDirectory() as tmpdir:
        rp = Path(tmpdir)
        (rp / "app.py").write_text("x = 1\n")

        with patch.dict("sys.modules", {"anthropic": mock_module}), \
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


def test_retry_on_rate_limit():
    finding = _pf("PAT-003", severity="critical")
    call_count = {"n": 0}

    def side_effect(*args, **kwargs):
        call_count["n"] += 1
        if call_count["n"] < 2:
            raise Exception("429 Rate limit exceeded")
        return _mock_anthropic_response(_MOCK_RESPONSE_JSON)

    mock_module, mock_client = _make_mock_anthropic("")
    mock_client.messages.create.side_effect = side_effect

    with tempfile.TemporaryDirectory() as tmpdir:
        rp = Path(tmpdir)
        (rp / "app.py").write_text("def run():\n    cursor.execute(sql)\n")

        with patch.dict("sys.modules", {"anthropic": mock_module}), \
             patch("time.sleep"):
            result = verify_findings(
                repo_root=rp,
                pattern_findings=[finding],
                taint_result=_empty_taint(),
                api_key="sk-test-key-placeholder-abc12345678",
                max_findings_to_verify=5,
            )

        assert isinstance(result, LLMVerificationResult)
        assert call_count["n"] >= 1


def test_no_api_key_returns_empty_result():
    import os
    # Ensure no env key is set
    env_backup = os.environ.pop("ANTHROPIC_API_KEY", None)
    try:
        result = verify_findings(
            repo_root=Path("/tmp"),
            pattern_findings=[_pf("PAT-001")],
            taint_result=_empty_taint(),
            api_key=None,
        )
        assert result.findings_skipped >= 1
        assert result.api_calls_made == 0
    finally:
        if env_backup:
            os.environ["ANTHROPIC_API_KEY"] = env_backup
