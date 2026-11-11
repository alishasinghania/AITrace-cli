"""
LLM Verifier — independent overlay assessment of uncertain findings via LLM.

Uses litellm for provider-agnostic routing (OpenAI, Anthropic, Ollama, etc.).
Only runs when --verify flag is passed.
Code context is redacted before any external API call.

Verification never mutates static finding fields (severity, confirmed_by_taint,
dismissed_as_fp). Verdicts live on VerificationResult.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

if TYPE_CHECKING:
    from core.analyzers.pattern_analyzer import PatternFinding
    from core.analyzers.crossfile_taint import CrossFileTaintResult
    from core.features.credentials.resolver import ProviderConfig

# ---------------------------------------------------------------------------
# Verdicts — overlay only; never mutate static findings
# ---------------------------------------------------------------------------

VERDICT_VERIFIED = "VERIFIED"
VERDICT_FALSE_POSITIVE = "FALSE_POSITIVE"
VERDICT_INCONCLUSIVE = "INCONCLUSIVE"
VERDICT_ERROR = "ERROR"

_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_\.]{2,}")
_REASON_STOPWORDS = {
    "the", "and", "for", "from", "this", "that", "with", "without", "not",
    "code", "line", "file", "true", "false", "none", "def", "return", "import",
    "class", "has", "have", "been", "was", "are", "were", "can", "could",
    "would", "should", "real", "clear", "path", "finding", "because", "there",
    "here", "also", "only", "just", "very", "into", "over", "under", "static",
    "tool", "missed", "attacker", "input", "output", "value", "comes", "loaded",
    "environment", "hardcoded", "string", "previous", "instructions",
}


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
    verdict: str = ""
    evidence_refs: List[str] = field(default_factory=list)
    finding_file: str = ""
    finding_line: Optional[int] = None

    def __post_init__(self) -> None:
        """Align verdict with boolean flags for constructors that omit verdict."""
        if self.verdict:
            self.verdict = str(self.verdict).upper()
            self.verified = self.verdict == VERDICT_VERIFIED
            self.false_positive = self.verdict == VERDICT_FALSE_POSITIVE
            return
        if self.error:
            self.verdict = VERDICT_ERROR
            self.verified = False
            self.false_positive = False
        elif self.verified and self.false_positive:
            self.verdict = VERDICT_ERROR
            self.verified = False
            self.false_positive = False
            if not self.error:
                self.error = "contradictory_verdict"
        elif self.verified:
            self.verdict = VERDICT_VERIFIED
        elif self.false_positive:
            self.verdict = VERDICT_FALSE_POSITIVE
        else:
            self.verdict = VERDICT_INCONCLUSIVE

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
            "verdict": self.verdict,
            "evidence_refs": list(self.evidence_refs),
            "finding_file": self.finding_file,
            "finding_line": self.finding_line,
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
    findings_inconclusive: int = 0
    errors: List[str] = field(default_factory=list)
    selection_records: List[Dict[str, Any]] = field(default_factory=list)

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
            "findings_inconclusive": self.findings_inconclusive,
            "errors": list(self.errors),
            "selection_records": list(self.selection_records),
        }


@dataclass
class CandidateRecord:
    """Why a security finding was selected, skipped, duplicated, or overflowed."""

    identity_key: str
    finding_id: str
    file: str
    line: Optional[int]
    action: str
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "identity_key": self.identity_key,
            "finding_id": self.finding_id,
            "file": self.file,
            "line": self.line,
            "action": self.action,
            "reason": self.reason,
        }


def _meta(finding: Any) -> Dict[str, Any]:
    md = getattr(finding, "metadata", None) or {}
    return md if isinstance(md, dict) else {}


def _rule_id(finding: Any) -> str:
    return str(getattr(finding, "vulnerability_id", None) or getattr(finding, "id", "") or "")


def _file_of(finding: Any) -> str:
    try:
        from core.exporters.finding_contract import sink_location
        file, _line = sink_location(finding)
        if file:
            return str(file)
    except Exception:
        pass
    return str(getattr(finding, "file", "") or _meta(finding).get("sink_file") or "")


def _line_of(finding: Any) -> Optional[int]:
    try:
        from core.exporters.finding_contract import sink_location
        _file, line = sink_location(finding)
        return line
    except Exception:
        line = getattr(finding, "line", None)
        if line is None:
            line = _meta(finding).get("sink_line")
        try:
            return int(line) if line is not None else None
        except (TypeError, ValueError):
            return None


def finding_identity(finding: Any) -> Tuple[str, str, Optional[int]]:
    """Rule id + sink file + sink line — same identity HTML Security Findings use."""
    try:
        from core.exporters.finding_contract import finding_identity as canonical
        return canonical(finding)
    except Exception:
        return (_rule_id(finding), _file_of(finding), _line_of(finding))


def identity_key(finding: Any) -> str:
    """Pipe-joined identity string."""
    try:
        from core.exporters.finding_contract import identity_key as canonical
        return canonical(finding)
    except Exception:
        vid, file, line = finding_identity(finding)
        return f"{vid}|{file}|{'' if line is None else line}"


def _severity_str(finding: Any) -> str:
    sev = getattr(finding, "severity", "") or ""
    return str(getattr(sev, "value", sev) or "")


def _confidence_of(finding: Any) -> str:
    return str(getattr(finding, "confidence", None) or _meta(finding).get("confidence") or "")


def _evidence_strings(finding: Any) -> List[str]:
    out: List[str] = []
    for item in getattr(finding, "evidence", None) or []:
        if isinstance(item, str):
            if item:
                out.append(item)
            continue
        desc = getattr(item, "description", None)
        if desc:
            out.append(str(desc))
    return out


def _taint_path_of(finding: Any) -> List[str]:
    path = getattr(finding, "taint_path", None)
    if path:
        return list(path)
    return list(_meta(finding).get("taint_path") or [])


def _confirmed_taint(finding: Any) -> bool:
    if getattr(finding, "confirmed_by_taint", False):
        return True
    return bool(_meta(finding).get("confirmed_by_taint"))


def _static_fp(finding: Any) -> bool:
    if getattr(finding, "dismissed_as_fp", False):
        return True
    return bool(_meta(finding).get("dismissed_as_fp"))


def _owasp_of(finding: Any) -> str:
    value = getattr(finding, "owasp_id", None)
    if value:
        return str(value)
    tags = list(getattr(finding, "tags", None) or [])
    return str(tags[0]) if tags else ""


def _cwe_of(finding: Any) -> str:
    value = getattr(finding, "cwe", None)
    if value:
        return str(value)
    tags = list(getattr(finding, "tags", None) or [])
    return str(tags[1]) if len(tags) > 1 else ""


def _framework_of(finding: Any) -> str:
    value = getattr(finding, "framework", None)
    if value:
        return str(value)
    tags = list(getattr(finding, "tags", None) or [])
    return str(tags[2]) if len(tags) > 2 else ""


def _pattern_of(finding: Any) -> str:
    return str(getattr(finding, "pattern_matched", None) or _meta(finding).get("pattern_matched") or "")


def _function_of(finding: Any) -> str:
    return str(getattr(finding, "function_name", None) or _meta(finding).get("function_name") or "")


def _cvss_of(finding: Any) -> float:
    raw = getattr(finding, "cvss_estimate", None)
    if raw is None:
        raw = _meta(finding).get("cvss_estimate")
    try:
        return float(raw or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _category_str(finding: Any) -> str:
    cat = getattr(finding, "category", "") or ""
    return str(getattr(cat, "value", cat) or "")


def _has_source_sink_evidence(finding: Any) -> bool:
    """True when a confirmed path or source location accompanies the sink."""
    hops = [h for h in _taint_path_of(finding) if "(sink not reached)" not in str(h)]
    source = getattr(finding, "source_file", None) or _meta(finding).get("source_file")
    return bool(hops) and (_confirmed_taint(finding) or bool(source))


def _is_pat_or_flow(finding: Any) -> bool:
    vid = _rule_id(finding)
    return vid.startswith("PAT-") or vid.startswith("FLOW-")


def _is_inventory(finding: Any) -> bool:
    try:
        from core.exporters.finding_contract import is_inventory_finding
        return bool(is_inventory_finding(finding))
    except Exception:
        return False


def verifier_failure_result(
    pattern_findings: List["PatternFinding"],
    message: str,
    provider: str = "",
    model: str = "",
) -> LLMVerificationResult:
    """Record a verifier-level failure without mutating findings."""
    return LLMVerificationResult(
        verifications=[],
        api_calls_made=0,
        findings_verified=0,
        findings_dismissed=0,
        findings_skipped=len(pattern_findings or []),
        findings_errored=1,
        total_tokens_used=0,
        provider_used=provider,
        model_used=model,
        errors=[message],
    )


def overlay_for_finding(
    llm_verification: Optional[LLMVerificationResult],
    finding: Any,
) -> Optional[VerificationResult]:
    """Return the overlay result for a finding identity, if any."""
    if llm_verification is None:
        return None
    want = finding_identity(finding)
    for result in getattr(llm_verification, "verifications", []) or []:
        got = (result.finding_id, result.finding_file or "", result.finding_line)
        if got == want:
            return result
    return None


def apply_overlay_to_findings(
    findings: List[Any],
    llm_verification: Optional[LLMVerificationResult],
) -> None:
    """Copy overlay verdicts onto Finding metadata. Never changes severity or taint."""
    if llm_verification is None:
        return
    try:
        from core.models import FindingCategory
    except Exception:
        FindingCategory = None  # type: ignore
    for finding in findings or []:
        overlay = overlay_for_finding(llm_verification, finding)
        if overlay is None:
            continue
        md = getattr(finding, "metadata", None)
        if isinstance(md, dict):
            md["llm_verdict"] = overlay.verdict
            md["confirmed_by_llm"] = overlay.verdict == VERDICT_VERIFIED
        cat = getattr(finding, "category", None)
        cat_val = getattr(cat, "value", cat)
        if (
            overlay.verdict == VERDICT_VERIFIED
            and cat_val != "taint_confirmed"
            and FindingCategory is not None
        ):
            try:
                finding.category = FindingCategory.LLM_VERIFIED
            except Exception:
                pass


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
        from core.features.credentials.redactor import redact_code_context
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

    rel = _file_of(finding)
    file_path = (repo_root / rel) if rel else repo_root
    try:
        source_text = file_path.read_text(encoding="utf-8", errors="ignore")
        source_lines = source_text.splitlines()
    except OSError:
        return context

    import_lines = source_lines[:30]
    context["imports"] = _redact_code("\n".join(
        f"# line {i + 1}: {l}" for i, l in enumerate(import_lines)
    ))

    line = _line_of(finding) or 1
    primary_fn = _read_function_context(file_path, line, source_lines)
    context["primary_function"] = _redact_code(primary_fn)

    taint_path = _taint_path_of(finding)
    if taint_path:
        hops = [h for h in taint_path if "(sink not reached)" not in h]
        context["taint_path_summary"] = "Taint path: " + " → ".join(hops)
    else:
        context["taint_path_summary"] = "Static taint analysis did not find a confirmed path."

    supporting_parts: List[str] = []
    token_budget = max_tokens - _estimate_tokens(
        context["imports"] + context["primary_function"] + context["taint_path_summary"]
    )

    graph = getattr(taint_result, "call_graph", {})
    hops_to_show = taint_path[:3]
    sink_file = _file_of(finding)
    for hop in hops_to_show:
        if "(sink not reached)" in hop or token_budget < 200:
            break
        node = graph.get(hop)
        if not node or node.file == sink_file:
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
# Finding selection — same pool/identity as HTML Security Findings
# ---------------------------------------------------------------------------

_PRIORITY_IDS = ["FLOW-RCE", "FLOW-SQL", "PAT-012", "PAT-013", "PAT-002", "PAT-003"]
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _priority_key(finding: Any) -> Tuple:
    """Deterministic high-risk, source-to-sink-first ordering."""
    vid, file, line = finding_identity(finding)
    taint_rank = 0 if _confirmed_taint(finding) else 1
    evidence_rank = 0 if _has_source_sink_evidence(finding) else 1
    sev_rank = _SEV_RANK.get(_severity_str(finding).lower(), 5)
    if vid in _PRIORITY_IDS:
        rule_rank = _PRIORITY_IDS.index(vid)
    elif vid.startswith("FLOW-"):
        rule_rank = len(_PRIORITY_IDS)
    elif vid.startswith("PAT-"):
        rule_rank = len(_PRIORITY_IDS) + 1
    else:
        rule_rank = len(_PRIORITY_IDS) + 2
    return (taint_rank, evidence_rank, sev_rank, rule_rank, vid, file, line or 0)


def _record_for(finding: Any, action: str, reason: str) -> CandidateRecord:
    vid, file, line = finding_identity(finding)
    return CandidateRecord(
        identity_key=f"{vid}|{file}|{'' if line is None else line}",
        finding_id=vid,
        file=file,
        line=line,
        action=action,
        reason=reason,
    )


def select_verification_candidates(
    findings: List[Any],
    max_findings: int = 10,
) -> Tuple[List[Any], List[CandidateRecord]]:
    """
    Choose PAT-*/FLOW-* security findings for LLM review.

    Includes taint-confirmed flows. Deduplicates by finding identity.
    Overflow past *max_findings* is recorded, not dropped silently.
    """
    records: List[CandidateRecord] = []
    eligible: List[Any] = []
    for finding in findings or []:
        if _is_inventory(finding):
            records.append(_record_for(finding, "skipped", "inventory"))
            continue
        if not _is_pat_or_flow(finding):
            records.append(_record_for(finding, "skipped", "not_pat_or_flow"))
            continue
        if _static_fp(finding):
            records.append(_record_for(finding, "skipped", "static_false_positive"))
            continue
        eligible.append(finding)

    eligible.sort(key=_priority_key)

    unique: List[Any] = []
    seen: set = set()
    for finding in eligible:
        key = _record_for(finding, "selected", "selected").identity_key
        if key in seen:
            records.append(_record_for(finding, "duplicate", "duplicate_identity"))
            continue
        seen.add(key)
        unique.append(finding)

    cap = max(0, int(max_findings))
    selected: List[Any] = []
    for index, finding in enumerate(unique):
        if index < cap:
            selected.append(finding)
            records.append(_record_for(finding, "selected", "selected"))
        else:
            records.append(_record_for(finding, "overflow", "review_limit"))
    return selected, records


def _select_findings(
    findings: List[Any],
    max_findings: int,
) -> List[Any]:
    """Backward-compatible wrapper: selected findings only."""
    selected, _records = select_verification_candidates(findings, max_findings)
    return selected


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
    "Your job is an independent assessment of whether each finding is exploitable in the "
    "specific snippet shown. Do not echo the static tool's title or severity as proof.\n\n"
    "Choose exactly one verdict:\n"
    "VERIFIED: a real attacker with external network access could exploit this with reasonable effort. "
    "reasoning must cite identifiers from the snippet (function, variable, file, or hop).\n"
    "FALSE POSITIVE: effective mitigations exist or the dangerous path is unreachable from external input. "
    "false_positive_reason must cite identifiers from the snippet.\n"
    "INCONCLUSIVE: the snippet and evidence are insufficient to confirm or dismiss.\n"
    "Never set verified and false_positive both true. Never invent files, functions, or hops "
    "that are not in the evidence. cvss_estimate must be a number from 0 to 10.\n\n"
    "Always respond with valid JSON only. No markdown fences, no explanation outside the JSON structure."
)


def _build_user_prompt(finding: Any, context: Dict[str, str]) -> str:
    evidence = "\n".join(_evidence_strings(finding))
    rel = _file_of(finding)
    return f"""Review this security finding from an AI application.

FINDING:
  ID: {_rule_id(finding)}
  Title: {getattr(finding, 'title', '')}
  Severity claimed: {_severity_str(finding)}
  Confidence: {_confidence_of(finding)}
  Category: {_category_str(finding)} ({_owasp_of(finding)})
  CWE: {_cwe_of(finding)}
  File: {rel}:{_line_of(finding) or 'unknown'}
  Framework: {_framework_of(finding)}
  Pattern matched: {_pattern_of(finding)}
  Taint confirmed: {_confirmed_taint(finding)}
  Evidence: {evidence}

CALL GRAPH CONTEXT:
{context['taint_path_summary']}

PRIMARY FUNCTION (from {rel}):
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
  "verdict": "VERIFIED_or_FALSE_POSITIVE_or_INCONCLUSIVE",
  "verified": true_or_false,
  "final_severity": "critical_or_high_or_medium_or_low",
  "confidence": "high_or_medium_or_low",
  "reasoning": "Two to four sentences citing function/variable/file names from the snippet",
  "attack_scenario": "Specific attack using only names shown, or empty string",
  "attack_payload": "Example malicious input string, or empty string if not applicable",
  "remediation": "Single specific fix referencing actual variable and function names shown",
  "false_positive": true_or_false,
  "false_positive_reason": "Specific reason citing snippet identifiers if false positive, else empty",
  "owasp_category": "e.g. LLM01 Prompt Injection",
  "cvss_estimate": numeric_0_to_10,
  "exploit_complexity": "low_or_medium_or_high",
  "requires_authentication": true_or_false
}}"""


_SIMPLIFIED_PROMPT = (
    "Respond with only this JSON (no markdown): "
    '{"verdict": "VERIFIED_or_FALSE_POSITIVE_or_INCONCLUSIVE", '
    '"verified": true_or_false, "false_positive": true_or_false, '
    '"reasoning": "one sentence citing a snippet identifier", '
    '"final_severity": "critical/high/medium/low", "cvss_estimate": 0}'
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
# Independent verdict assessment — never mutates findings
# ---------------------------------------------------------------------------

def _identifier_tokens(text: str) -> set:
    """Extract identifier-like tokens, dropping generic English words."""
    return {m.group().lower() for m in _IDENT_RE.finditer(text or "")} - _REASON_STOPWORDS


def collect_evidence_refs(
    finding: Any,
    context: Optional[Dict[str, str]] = None,
) -> List[str]:
    """Collect concrete evidence strings the model must cite."""
    refs: List[str] = []
    file_path = _file_of(finding)
    if file_path:
        refs.append(file_path)
        name = Path(file_path).name
        if name:
            refs.append(name)
        stem = Path(file_path).stem
        if stem and stem not in ("app", "main", "index", "utils", "helpers"):
            refs.append(stem)
    func = _function_of(finding)
    if func:
        refs.append(func)
    pattern = _pattern_of(finding)
    if pattern and len(pattern) >= 4:
        refs.append(pattern)
    for item in _evidence_strings(finding):
        refs.append(item)
    for hop in _taint_path_of(finding):
        if hop and "(sink not reached)" not in hop:
            refs.append(str(hop))
    ctx = context or {}
    for key in ("primary_function", "taint_path_summary", "imports", "supporting_functions"):
        value = ctx.get(key) or ""
        if value and value not in ("Not available.", "Static taint analysis did not find a confirmed path."):
            refs.append(value)
    # Deduplicate while preserving order
    seen: set = set()
    unique: List[str] = []
    for ref in refs:
        key = ref.strip()
        if not key or key in seen:
            continue
        seen.add(key)
        unique.append(key)
    return unique


def reason_supported_by_evidence(reason: str, evidence_refs: List[str]) -> bool:
    """True when reasoning cites at least one concrete evidence identifier."""
    text = (reason or "").strip()
    if not text or not evidence_refs:
        return False
    lowered = text.lower()
    for ref in evidence_refs:
        snippet = (ref or "").strip()
        if len(snippet) >= 8 and snippet.lower() in lowered:
            return True
    reason_tokens = _identifier_tokens(text)
    haystack: set = set()
    for ref in evidence_refs:
        haystack |= _identifier_tokens(ref)
    return bool(reason_tokens & haystack)


def _as_optional_bool(value: Any) -> Optional[bool]:
    """Parse a JSON flag; None means the key was omitted or unreadable."""
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in ("true", "yes", "1"):
            return True
        if lowered in ("false", "no", "0"):
            return False
    return None


def _parse_cvss(value: Any, default: float) -> Tuple[float, Optional[str]]:
    """Return (cvss, error). Invalid numeric values are rejected, not coerced."""
    if value is None or value == "":
        try:
            return float(default), None
        except (TypeError, ValueError):
            return 0.0, None
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return float(default) if default == default else 0.0, "invalid_cvss"
    if parsed != parsed or parsed < 0.0 or parsed > 10.0:
        return float(default) if default == default else 0.0, "invalid_cvss"
    return parsed, None


def assess_model_payload(
    finding: "PatternFinding",
    parsed: Optional[Dict[str, Any]],
    context: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """
    Independently map a model payload to a verdict.

    Returns a dict with verdict, error, evidence_refs, reasoning, and cvss.
    Does not mutate *finding*.
    """
    refs = collect_evidence_refs(finding, context)
    if parsed is None:
        return {
            "verdict": VERDICT_ERROR,
            "error": "malformed_response",
            "evidence_refs": refs,
            "reasoning": "",
            "cvss_estimate": _cvss_of(finding),
        }

    cvss, cvss_error = _parse_cvss(
        parsed.get("cvss_estimate"),
        _cvss_of(finding),
    )
    if cvss_error:
        return {
            "verdict": VERDICT_ERROR,
            "error": cvss_error,
            "evidence_refs": refs,
            "reasoning": str(parsed.get("reasoning") or ""),
            "cvss_estimate": cvss,
        }

    verified = _as_optional_bool(parsed.get("verified"))
    false_positive = _as_optional_bool(parsed.get("false_positive"))
    verdict_raw = str(parsed.get("verdict") or "").strip().upper().replace(" ", "_")
    if verdict_raw in ("FALSEPOSITIVE", "FALSE_POSITIVE", "FP"):
        verdict_raw = VERDICT_FALSE_POSITIVE

    if verified is True and false_positive is True:
        return {
            "verdict": VERDICT_ERROR,
            "error": "contradictory_verdict",
            "evidence_refs": refs,
            "reasoning": str(parsed.get("reasoning") or ""),
            "cvss_estimate": cvss,
        }
    if verdict_raw == VERDICT_VERIFIED and false_positive is True:
        return {
            "verdict": VERDICT_ERROR,
            "error": "contradictory_verdict",
            "evidence_refs": refs,
            "reasoning": str(parsed.get("reasoning") or ""),
            "cvss_estimate": cvss,
        }
    if verdict_raw == VERDICT_FALSE_POSITIVE and verified is True:
        return {
            "verdict": VERDICT_ERROR,
            "error": "contradictory_verdict",
            "evidence_refs": refs,
            "reasoning": str(parsed.get("reasoning") or ""),
            "cvss_estimate": cvss,
        }

    reasoning = str(parsed.get("reasoning") or "").strip()
    fp_reason = str(parsed.get("false_positive_reason") or "").strip()

    wants_verified = verified is True or verdict_raw == VERDICT_VERIFIED
    wants_fp = false_positive is True or verdict_raw == VERDICT_FALSE_POSITIVE

    if wants_verified and not wants_fp:
        if not reasoning:
            return {
                "verdict": VERDICT_INCONCLUSIVE,
                "error": None,
                "evidence_refs": refs,
                "reasoning": "",
                "cvss_estimate": cvss,
                "note": "empty_reasoning",
            }
        if not refs:
            return {
                "verdict": VERDICT_INCONCLUSIVE,
                "error": None,
                "evidence_refs": refs,
                "reasoning": reasoning,
                "cvss_estimate": cvss,
                "note": "missing_evidence",
            }
        if not reason_supported_by_evidence(reasoning, refs):
            return {
                "verdict": VERDICT_INCONCLUSIVE,
                "error": None,
                "evidence_refs": refs,
                "reasoning": reasoning,
                "cvss_estimate": cvss,
                "note": "unsupported_reason",
            }
        return {
            "verdict": VERDICT_VERIFIED,
            "error": None,
            "evidence_refs": refs,
            "reasoning": reasoning,
            "cvss_estimate": cvss,
        }

    if wants_fp and not wants_verified:
        reason = fp_reason or reasoning
        if not reason:
            return {
                "verdict": VERDICT_INCONCLUSIVE,
                "error": None,
                "evidence_refs": refs,
                "reasoning": "",
                "cvss_estimate": cvss,
                "note": "empty_reasoning",
            }
        if not refs:
            return {
                "verdict": VERDICT_INCONCLUSIVE,
                "error": None,
                "evidence_refs": refs,
                "reasoning": reason,
                "cvss_estimate": cvss,
                "note": "missing_evidence",
            }
        if not reason_supported_by_evidence(reason, refs):
            return {
                "verdict": VERDICT_INCONCLUSIVE,
                "error": None,
                "evidence_refs": refs,
                "reasoning": reason,
                "cvss_estimate": cvss,
                "note": "unsupported_reason",
            }
        return {
            "verdict": VERDICT_FALSE_POSITIVE,
            "error": None,
            "evidence_refs": refs,
            "reasoning": reason,
            "cvss_estimate": cvss,
        }

    return {
        "verdict": VERDICT_INCONCLUSIVE,
        "error": None,
        "evidence_refs": refs,
        "reasoning": reasoning or fp_reason,
        "cvss_estimate": cvss,
        "note": "no_positive_verdict",
    }


def _error_overlay(
    finding: "PatternFinding",
    model: str,
    provider: str,
    tokens: int,
    elapsed_ms: int,
    error: str,
    evidence_refs: Optional[List[str]] = None,
) -> VerificationResult:
    """Build an ERROR overlay that leaves the original finding untouched."""
    return VerificationResult(
        finding_id=_rule_id(finding),
        original_severity=_severity_str(finding),
        verified=False,
        final_severity=_severity_str(finding),
        confidence=_confidence_of(finding),
        reasoning="",
        attack_scenario="",
        attack_payload="",
        remediation="",
        false_positive=False,
        false_positive_reason="",
        owasp_category=_owasp_of(finding),
        cvss_estimate=_cvss_of(finding),
        exploit_complexity="medium",
        requires_authentication=False,
        model_used=model,
        provider=provider,
        tokens_used=tokens,
        latency_ms=elapsed_ms,
        verification_time_ms=elapsed_ms,
        error=error,
        verdict=VERDICT_ERROR,
        evidence_refs=list(evidence_refs or []),
        finding_file=_file_of(finding),
        finding_line=_line_of(finding),
    )


def _build_verification_result(
    finding: "PatternFinding",
    parsed: Optional[Dict[str, Any]],
    model: str,
    provider: str,
    tokens: int,
    elapsed_ms: int,
    context: Optional[Dict[str, str]] = None,
    error: Optional[str] = None,
) -> VerificationResult:
    """Build an overlay VerificationResult. Never mutates *finding*."""
    if error and parsed is None:
        return _error_overlay(finding, model, provider, tokens, elapsed_ms, error)

    decision = assess_model_payload(finding, parsed, context)
    verdict = decision["verdict"]
    decision_error = decision.get("error") or error
    reasoning = str(decision.get("reasoning") or "")
    parsed = parsed or {}
    fp_reason = str(parsed.get("false_positive_reason") or "")
    if verdict == VERDICT_FALSE_POSITIVE and not fp_reason:
        fp_reason = reasoning

    original_severity = _severity_str(finding)
    claimed_severity = str(parsed.get("final_severity") or original_severity)
    if verdict in (VERDICT_ERROR, VERDICT_INCONCLUSIVE):
        claimed_severity = original_severity

    return VerificationResult(
        finding_id=_rule_id(finding),
        original_severity=original_severity,
        verified=verdict == VERDICT_VERIFIED,
        final_severity=claimed_severity,
        confidence=str(parsed.get("confidence") or _confidence_of(finding)),
        reasoning=reasoning,
        attack_scenario=str(parsed.get("attack_scenario") or ""),
        attack_payload=str(parsed.get("attack_payload") or ""),
        remediation=str(parsed.get("remediation") or ""),
        false_positive=verdict == VERDICT_FALSE_POSITIVE,
        false_positive_reason=fp_reason if verdict == VERDICT_FALSE_POSITIVE else "",
        owasp_category=str(parsed.get("owasp_category") or _owasp_of(finding)),
        cvss_estimate=float(decision.get("cvss_estimate") or 0.0),
        exploit_complexity=str(parsed.get("exploit_complexity") or "medium"),
        requires_authentication=bool(parsed.get("requires_authentication", False)),
        model_used=model,
        provider=provider,
        tokens_used=tokens,
        latency_ms=elapsed_ms,
        verification_time_ms=elapsed_ms,
        error=decision_error,
        verdict=verdict,
        evidence_refs=list(decision.get("evidence_refs") or []),
        finding_file=_file_of(finding),
        finding_line=_line_of(finding),
    )


def _apply_verification(finding: "PatternFinding", result: VerificationResult) -> None:
    """
    Intentionally a no-op.

    LLM verification is an independent overlay. Static fields (severity,
    confirmed_by_taint, dismissed_as_fp) must not change based on the model.
    Kept so older call sites remain import-safe.
    """
    return None


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

    Results are an independent overlay. Static finding fields are never mutated.
    Credential resolution is handled by ProviderConfig (passed by engine.py).
    The legacy api_key/model parameters are still accepted for backwards compat.
    """
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

    try:
        import litellm  # noqa: F401
    except ImportError:
        return verifier_failure_result(
            pattern_findings,
            "litellm_not_installed",
            provider=resolved_provider,
            model=resolved_model,
        )

    repo_root = Path(repo_root).resolve()
    selected, selection_records = select_verification_candidates(
        pattern_findings, max_findings_to_verify
    )
    skipped = sum(1 for rec in selection_records if rec.action != "selected")

    verifications: List[VerificationResult] = []
    recorded_errors: List[str] = []
    api_calls = 0
    total_tokens = 0
    n_verified = 0
    n_dismissed = 0
    n_errored = 0
    n_inconclusive = 0

    for finding in selected:
        try:
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
                    vr = _error_overlay(
                        finding,
                        resolved_model,
                        resolved_provider,
                        tokens2,
                        elapsed_ms,
                        error2 or "empty_response",
                    )
                    verifications.append(vr)
                    n_errored += 1
                    recorded_errors.append(vr.error or "empty_response")
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
                parsed = _parse_llm_response(text3) if text3 else None
                if parsed is None:
                    vr = _error_overlay(
                        finding,
                        resolved_model,
                        resolved_provider,
                        tokens3,
                        elapsed_ms,
                        error3 or "parse_failed",
                    )
                    verifications.append(vr)
                    n_errored += 1
                    recorded_errors.append(vr.error or "parse_failed")
                    continue

            vr = _build_verification_result(
                finding, parsed, resolved_model, resolved_provider,
                tokens, elapsed_ms, context=context,
            )
            verifications.append(vr)
            # Overlay only — do not mutate finding.severity / taint / dismissed_as_fp.
            if vr.verdict == VERDICT_VERIFIED:
                n_verified += 1
            elif vr.verdict == VERDICT_FALSE_POSITIVE:
                n_dismissed += 1
            elif vr.verdict == VERDICT_ERROR:
                n_errored += 1
                if vr.error:
                    recorded_errors.append(vr.error)
            else:
                n_inconclusive += 1
        except Exception as exc:
            message = f"verifier_exception: {type(exc).__name__}: {exc}"
            vr = _error_overlay(
                finding, resolved_model, resolved_provider, 0, 0, message
            )
            verifications.append(vr)
            n_errored += 1
            recorded_errors.append(message)

    if provider_config is not None:
        try:
            provider_config.clear_key()
        except Exception:
            recorded_errors.append("failed_to_clear_provider_key")

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
        findings_inconclusive=n_inconclusive,
        errors=recorded_errors,
        selection_records=[rec.to_dict() for rec in selection_records],
    )
