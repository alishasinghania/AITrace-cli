"""
LLM Verifier — semantically verifies uncertain security findings via LLM.

Uses litellm for provider-agnostic routing (OpenAI, Anthropic, Ollama, etc.).
Only runs when --verify flag is passed.
Code context is redacted before any external API call.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

if TYPE_CHECKING:
    from core.pattern_analyzer import PatternFinding
    from core.crossfile_taint import CrossFileTaintResult
    from core.credentials.resolver import ProviderConfig

# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class VerificationResult:
    finding_id: str
    original_severity: str
    verified: bool
    final_severity: str
    confidence: str
    reasoning: str
    attack_scenario: str
    attack_payload: str
    remediation: str
    false_positive: bool
    false_positive_reason: str
    owasp_category: str
    cvss_estimate: float
    exploit_complexity: str        # "low" | "medium" | "high"
    requires_authentication: bool
    model_used: str
    provider: str
    tokens_used: int
    latency_ms: int
    verification_time_ms: int      # alias for latency_ms (backwards compat)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "original_severity": self.original_severity,
            "verified": self.verified,
            "final_severity": self.final_severity,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
            "attack_scenario": self.attack_scenario,
            "attack_payload": self.attack_payload,
            "remediation": self.remediation,
            "false_positive": self.false_positive,
            "false_positive_reason": self.false_positive_reason,
            "owasp_category": self.owasp_category,
            "cvss_estimate": self.cvss_estimate,
            "exploit_complexity": self.exploit_complexity,
            "requires_authentication": self.requires_authentication,
            "model_used": self.model_used,
            "provider": self.provider,
            "tokens_used": self.tokens_used,
            "latency_ms": self.latency_ms,
            "verification_time_ms": self.verification_time_ms,
            "error": self.error,
        }


@dataclass
class LLMVerificationResult:
    verifications: List[VerificationResult]
    api_calls_made: int
    findings_verified: int
    findings_dismissed: int
    findings_skipped: int
    findings_errored: int
    total_tokens_used: int
    provider_used: str = ""
    model_used: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verifications": [v.to_dict() for v in self.verifications],
            "api_calls_made": self.api_calls_made,
            "findings_verified": self.findings_verified,
            "findings_dismissed": self.findings_dismissed,
            "findings_skipped": self.findings_skipped,
            "findings_errored": self.findings_errored,
            "total_tokens_used": self.total_tokens_used,
            "provider_used": self.provider_used,
            "model_used": self.model_used,
        }


# ---------------------------------------------------------------------------
# Context building (public — used by engine.py and tests)
# ---------------------------------------------------------------------------

def build_verification_context(
    repo_root: Path,
    finding: "PatternFinding",
    taint_result: "CrossFileTaintResult",
    max_tokens: int = 3500,
) -> Dict[str, str]:
    """
    Build the code context dict for *finding*.

    Public so that engine.py and tests can call it without going through
    the full verification pipeline.
    """
    return _gather_context(repo_root, finding, taint_result, max_tokens)


# ---------------------------------------------------------------------------
# Redaction — delegates to credentials.redactor, falls back to local copy
# ---------------------------------------------------------------------------

def _redact_code(code: str) -> str:
    """Apply privacy redaction before sending code to an external API."""
    try:
        from core.credentials.redactor import redact_code_context
        return redact_code_context(code)
    except ImportError:
        pass
    # Minimal local fallback (subset of patterns)
    _local_patterns = [
        (re.compile(r'sk-[A-Za-z0-9]{20,}'), '[REDACTED_API_KEY]'),
        (re.compile(r'(?i)bearer\s+[A-Za-z0-9_\-]{20,}'), '[REDACTED_TOKEN]'),
        (re.compile(r'AKIA[0-9A-Z]{16}'), '[REDACTED_AWS_KEY]'),
        (re.compile(r'(?i)(password|passwd|secret|api_key)\s*=\s*["\'][^"\']{8,}["\']'), r'\1=[REDACTED]'),
    ]
    for pattern, replacement in _local_patterns:
        try:
            code = pattern.sub(replacement, code)
        except Exception:
            pass
    return code


# ---------------------------------------------------------------------------
# Context gathering
# ---------------------------------------------------------------------------

def _read_function_context(file_path: Path, line: int, source_lines: List[str]) -> str:
    """Extract the function containing 'line' with surrounding context."""
    import ast
    try:
        source = "\n".join(source_lines)
        tree = ast.parse(source)
    except Exception:
        start = max(0, line - 10)
        end = min(len(source_lines), line + 30)
        return "\n".join(
            f"# line {i + 1}: {l}" for i, l in enumerate(source_lines[start:end], start=start)
        )

    best_func = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            end_ln = getattr(node, "end_lineno", node.lineno + 50)
            if node.lineno <= line <= end_ln:
                if best_func is None or node.lineno >= best_func.lineno:
                    best_func = node

    if best_func is None:
        start = max(0, line - 10)
        end = min(len(source_lines), line + 30)
        return "\n".join(
            f"# line {i + 1}: {l}" for i, l in enumerate(source_lines[start:end], start=start)
        )

    start = max(0, best_func.lineno - 6)
    end = min(len(source_lines), getattr(best_func, "end_lineno", best_func.lineno + 50))
    return "\n".join(
        f"# line {i + 1}: {l}" for i, l in enumerate(source_lines[start:end], start=start)
    )


def _estimate_tokens(text: str) -> int:
    return len(text) // 4


def _gather_context(
    repo_root: Path,
    finding: "PatternFinding",
    taint_result: "CrossFileTaintResult",
    max_tokens: int = 3500,
) -> Dict[str, str]:
    context: Dict[str, str] = {
        "primary_function": "",
        "imports": "",
        "supporting_functions": "",
        "taint_path_summary": "",
    }

    file_path = repo_root / finding.file
    try:
        source_text = file_path.read_text(encoding="utf-8", errors="ignore")
        source_lines = source_text.splitlines()
    except OSError:
        return context

    import_lines = source_lines[:30]
    context["imports"] = _redact_code("\n".join(
        f"# line {i + 1}: {l}" for i, l in enumerate(import_lines)
    ))

    line = finding.line or 1
    primary_fn = _read_function_context(file_path, line, source_lines)
    context["primary_function"] = _redact_code(primary_fn)

    if finding.taint_path:
        hops = [h for h in finding.taint_path if "(sink not reached)" not in h]
        context["taint_path_summary"] = "Taint path: " + " → ".join(hops)
    else:
        context["taint_path_summary"] = "Static taint analysis did not find a confirmed path."

    supporting_parts: List[str] = []
    token_budget = max_tokens - _estimate_tokens(
        context["imports"] + context["primary_function"] + context["taint_path_summary"]
    )

    graph = getattr(taint_result, "call_graph", {})
    hops_to_show = finding.taint_path[:3] if finding.taint_path else []
    for hop in hops_to_show:
        if "(sink not reached)" in hop or token_budget < 200:
            break
        node = graph.get(hop)
        if not node or node.file == finding.file:
            continue
        try:
            hop_file = repo_root / node.file
            hop_lines = hop_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            fn_ctx = _read_function_context(hop_file, node.line_start, hop_lines)
            fn_ctx_redacted = _redact_code(fn_ctx)
            tokens = _estimate_tokens(fn_ctx_redacted)
            if tokens <= token_budget:
                supporting_parts.append(f"# From {node.file}:\n{fn_ctx_redacted}")
                token_budget -= tokens
        except OSError:
            continue

    context["supporting_functions"] = "\n\n".join(supporting_parts) if supporting_parts else "Not available."
    return context


# ---------------------------------------------------------------------------
# Finding selection
# ---------------------------------------------------------------------------

_PRIORITY_ORDER = ["PAT-012", "PAT-013", "PAT-002", "PAT-003"]


def _select_findings(
    findings: List["PatternFinding"],
    max_findings: int,
) -> List["PatternFinding"]:
    skippable: set = set()
    for f in findings:
        if f.confirmed_by_taint:
            skippable.add(id(f))
        if f.severity in ("low", "info"):
            skippable.add(id(f))
        if f.dismissed_as_fp:
            skippable.add(id(f))
        if f.file and any(t in f.file for t in ("test", "spec", "fixture")):
            skippable.add(id(f))

    candidates = [f for f in findings if id(f) not in skippable]

    def priority_key(f: "PatternFinding") -> int:
        if f.vulnerability_id in _PRIORITY_ORDER:
            return _PRIORITY_ORDER.index(f.vulnerability_id)
        if f.severity == "critical":
            return len(_PRIORITY_ORDER)
        if f.severity == "high":
            return len(_PRIORITY_ORDER) + 1
        return len(_PRIORITY_ORDER) + 2

    candidates.sort(key=priority_key)
    return candidates[:max_findings]


# ---------------------------------------------------------------------------
# Prompt templates
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = (
    "You are a principal security engineer specializing in AI application security, "
    "LLM vulnerabilities, prompt injection, agentic AI systems, and the OWASP LLM Top 10 2025 "
    "and OWASP Top 10 for Agentic Applications 2026. You have deep expertise in Python, FastAPI, "
    "Flask, LangChain, LlamaIndex, CrewAI, LangGraph, OpenAI Agents SDK, Pydantic AI, Smolagents, "
    "AutoGen, DSPy, and all major AI frameworks.\n\n"
    "You are reviewing automated security findings from AITrace, a static analysis tool. "
    "Your job is to determine if each finding represents a real, exploitable vulnerability "
    "in the specific codebase shown.\n\n"
    "Be skeptical but thorough:\n"
    "VERIFIED: a real attacker with external network access could exploit this with reasonable effort "
    "(no physical access, no insider required)\n"
    "FALSE POSITIVE: the code has effective mitigations the static tool missed, or the dangerous "
    "code path is unreachable from external input\n\n"
    "Always respond with valid JSON only. No markdown fences, no explanation outside the JSON structure."
)


def _build_user_prompt(finding: "PatternFinding", context: Dict[str, str]) -> str:
    return f"""Review this security finding from an AI application.

FINDING:
  ID: {finding.vulnerability_id}
  Title: {finding.title}
  Severity claimed: {finding.severity}
  Confidence: {finding.confidence}
  Category: {finding.category} ({finding.owasp_id})
  CWE: {finding.cwe}
  File: {finding.file}:{finding.line or 'unknown'}
  Framework: {finding.framework}
  Pattern matched: {finding.pattern_matched}
  Taint confirmed: {finding.confirmed_by_taint}
  Evidence: {chr(10).join(finding.evidence)}

CALL GRAPH CONTEXT:
{context['taint_path_summary']}

PRIMARY FUNCTION (from {finding.file}):
{context['primary_function']}

IMPORTS IN FILE:
{context['imports']}

SUPPORTING FUNCTIONS:
{context['supporting_functions']}

ASSESS:
1. Is this code reachable from external input?
2. Can an attacker control the value reaching the dangerous sink?
3. Are there mitigations the static tool may have missed?
4. What is the realistic attack scenario and worst-case impact?

Respond in this exact JSON (no other text):
{{
  "verified": true_or_false,
  "final_severity": "critical_or_high_or_medium_or_low",
  "confidence": "high_or_medium_or_low",
  "reasoning": "Two to four sentences explaining your conclusion",
  "attack_scenario": "Specific attack: what attacker sends, what path executes, what impact",
  "attack_payload": "Example malicious input string, or empty string if not applicable",
  "remediation": "Single specific fix referencing actual variable and function names shown",
  "false_positive": true_or_false,
  "false_positive_reason": "Specific reason if false positive, else empty string",
  "owasp_category": "e.g. LLM01 Prompt Injection",
  "cvss_estimate": numeric_0_to_10,
  "exploit_complexity": "low_or_medium_or_high",
  "requires_authentication": true_or_false
}}"""


_SIMPLIFIED_PROMPT = (
    "Respond with only this JSON (no markdown): "
    '{"verified": true_or_false, "false_positive": true_or_false, '
    '"reasoning": "one sentence", "final_severity": "critical/high/medium/low"}'
)


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------

def _strip_markdown_fences(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        lines = [l for l in lines if not l.strip().startswith("```")]
        text = "\n".join(lines).strip()
    return text


def _parse_llm_response(text: str) -> Optional[Dict[str, Any]]:
    text = _strip_markdown_fences(text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r'\{.*\}', text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group())
            except json.JSONDecodeError:
                pass
    return None


# ---------------------------------------------------------------------------
# litellm API call
# ---------------------------------------------------------------------------

def _call_litellm(
    model: str,
    api_key: Optional[str],
    base_url: Optional[str],
    prompt: str,
    simplified: bool = False,
) -> Tuple[Optional[str], int, Optional[str]]:
    """
    Call litellm with retry. Returns (response_text, tokens_used, error).
    api_key is passed as a local parameter — never stored or logged.
    """
    try:
        import litellm  # type: ignore
    except ImportError:
        return None, 0, "litellm not installed — run: pip install 'aitrace-cli[verify]'"

    system = _SYSTEM_PROMPT
    user = _SIMPLIFIED_PROMPT if simplified else prompt

    kwargs: Dict[str, Any] = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "max_tokens": 1024,
    }
    if api_key:
        kwargs["api_key"] = api_key
    if base_url:
        kwargs["base_url"] = base_url

    backoff = 2
    for attempt in range(3):
        try:
            response = litellm.completion(**kwargs)
            text = ""
            if response.choices:
                text = response.choices[0].message.content or ""
            usage = getattr(response, "usage", None)
            tokens = 0
            if usage:
                tokens = getattr(usage, "total_tokens", 0) or (
                    getattr(usage, "prompt_tokens", 0) + getattr(usage, "completion_tokens", 0)
                )
            return text, tokens, None
        except Exception as exc:
            err_str = str(exc)
            # Rate limit / overloaded — retry with backoff
            if any(code in err_str for code in ("429", "529", "rate_limit", "overloaded")):
                if attempt < 2:
                    time.sleep(backoff)
                    backoff *= 2
                    continue
            return None, 0, err_str

    return None, 0, "max_retries_exceeded"


# ---------------------------------------------------------------------------
# Result construction
# ---------------------------------------------------------------------------

def _build_verification_result(
    finding: "PatternFinding",
    parsed: Dict[str, Any],
    model: str,
    provider: str,
    tokens: int,
    elapsed_ms: int,
    error: Optional[str] = None,
) -> VerificationResult:
    return VerificationResult(
        finding_id=finding.vulnerability_id,
        original_severity=finding.severity,
        verified=bool(parsed.get("verified", False)),
        final_severity=str(parsed.get("final_severity", finding.severity)),
        confidence=str(parsed.get("confidence", finding.confidence)),
        reasoning=str(parsed.get("reasoning", "")),
        attack_scenario=str(parsed.get("attack_scenario", "")),
        attack_payload=str(parsed.get("attack_payload", "")),
        remediation=str(parsed.get("remediation", "")),
        false_positive=bool(parsed.get("false_positive", False)),
        false_positive_reason=str(parsed.get("false_positive_reason", "")),
        owasp_category=str(parsed.get("owasp_category", finding.owasp_id)),
        cvss_estimate=float(parsed.get("cvss_estimate", finding.cvss_estimate)),
        exploit_complexity=str(parsed.get("exploit_complexity", "medium")),
        requires_authentication=bool(parsed.get("requires_authentication", False)),
        model_used=model,
        provider=provider,
        tokens_used=tokens,
        latency_ms=elapsed_ms,
        verification_time_ms=elapsed_ms,
        error=error,
    )


def _apply_verification(finding: "PatternFinding", result: VerificationResult) -> None:
    if result.error:
        return
    if result.verified:
        finding.confirmed_by_llm = True
        finding.llm_reasoning = result.reasoning
        finding.remediation = result.remediation
        if result.final_severity != finding.severity:
            finding.severity = result.final_severity
    if result.false_positive:
        finding.dismissed_as_fp = True
        finding.llm_reasoning = result.false_positive_reason


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def verify_findings(
    repo_root: Path,
    pattern_findings: List["PatternFinding"],
    taint_result: "CrossFileTaintResult",
    provider_config: Optional["ProviderConfig"] = None,
    # Legacy parameters — kept for backwards compatibility with existing tests
    api_key: Optional[str] = None,
    model: str = "claude-haiku-4-5-20251001",
    max_findings_to_verify: int = 10,
) -> LLMVerificationResult:
    """
    Semantically verify uncertain findings using an LLM via litellm.

    Credential resolution is handled by ProviderConfig (passed by engine.py).
    The legacy api_key/model parameters are still accepted for backwards compat.
    """
    _empty = LLMVerificationResult(
        verifications=[],
        api_calls_made=0,
        findings_verified=0,
        findings_dismissed=0,
        findings_skipped=len(pattern_findings),
        findings_errored=0,
        total_tokens_used=0,
    )

    # Resolve model + key from provider_config (preferred) or legacy params
    resolved_model = model
    resolved_key: Optional[str] = None
    resolved_provider = "anthropic"
    resolved_base_url: Optional[str] = None

    if provider_config is not None:
        resolved_model = provider_config.model
        resolved_key = provider_config.api_key
        resolved_provider = provider_config.provider
        resolved_base_url = provider_config.base_url
    elif api_key:
        resolved_key = api_key
    else:
        # No provider config — try litellm without explicit key
        # (litellm will pick up env vars itself)
        pass

    # Verify litellm is importable
    try:
        import litellm  # noqa: F401
    except ImportError:
        return _empty

    repo_root = Path(repo_root).resolve()
    selected = _select_findings(pattern_findings, max_findings_to_verify)
    skipped = len(pattern_findings) - len(selected)

    verifications: List[VerificationResult] = []
    api_calls = 0
    total_tokens = 0
    n_verified = 0
    n_dismissed = 0
    n_errored = 0

    for finding in selected:
        time.sleep(0.1)

        context = _gather_context(repo_root, finding, taint_result)
        prompt = _build_user_prompt(finding, context)

        start = time.time()
        text, tokens, error = _call_litellm(
            resolved_model, resolved_key, resolved_base_url, prompt
        )
        elapsed_ms = int((time.time() - start) * 1000)
        api_calls += 1
        total_tokens += tokens

        if error or not text:
            time.sleep(0.1)
            text2, tokens2, error2 = _call_litellm(
                resolved_model, resolved_key, resolved_base_url, prompt, simplified=True
            )
            api_calls += 1
            total_tokens += tokens2
            if error2 or not text2:
                vr = VerificationResult(
                    finding_id=finding.vulnerability_id,
                    original_severity=finding.severity,
                    verified=False,
                    final_severity=finding.severity,
                    confidence=finding.confidence,
                    reasoning="",
                    attack_scenario="",
                    attack_payload="",
                    remediation="",
                    false_positive=False,
                    false_positive_reason="",
                    owasp_category=finding.owasp_id,
                    cvss_estimate=finding.cvss_estimate,
                    exploit_complexity="medium",
                    requires_authentication=False,
                    model_used=resolved_model,
                    provider=resolved_provider,
                    tokens_used=tokens2,
                    latency_ms=elapsed_ms,
                    verification_time_ms=elapsed_ms,
                    error=error2 or "empty_response",
                )
                verifications.append(vr)
                n_errored += 1
                continue
            text = text2
            tokens = tokens2

        parsed = _parse_llm_response(text)
        if parsed is None:
            time.sleep(0.1)
            text3, tokens3, error3 = _call_litellm(
                resolved_model, resolved_key, resolved_base_url, prompt, simplified=True
            )
            api_calls += 1
            total_tokens += tokens3
            parsed = (_parse_llm_response(text3) if text3 else None) or {}

        vr = _build_verification_result(
            finding, parsed, resolved_model, resolved_provider,
            tokens, elapsed_ms,
            error=None if parsed else "parse_failed",
        )
        verifications.append(vr)
        _apply_verification(finding, vr)

        if vr.verified:
            n_verified += 1
        if vr.false_positive:
            n_dismissed += 1
        if vr.error:
            n_errored += 1

    # Clear key from provider_config after all calls
    if provider_config is not None:
        provider_config.clear_key()

    return LLMVerificationResult(
        verifications=verifications,
        api_calls_made=api_calls,
        findings_verified=n_verified,
        findings_dismissed=n_dismissed,
        findings_skipped=skipped,
        findings_errored=n_errored,
        total_tokens_used=total_tokens,
        provider_used=resolved_provider,
        model_used=resolved_model,
    )
