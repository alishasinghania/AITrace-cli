from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from ..models import AIBOM, Finding, PolicyReport, PolicyRuleResult, Severity


@dataclass
class PolicyConfig:
    raw: Dict[str, Any]


def load_policy(path: Path) -> PolicyConfig:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return PolicyConfig(raw=data)


def _eval_license_rules(policy: Dict[str, Any], aibom: AIBOM) -> Optional[PolicyRuleResult]:
    license_cfg = policy.get("licenses")
    if not isinstance(license_cfg, dict):
        return None

    allowed = set(map(str.lower, license_cfg.get("allowed", []) or []))
    denied = set(map(str.lower, license_cfg.get("denied", []) or []))
    fail_build = bool(license_cfg.get("fail_build", True))

    violating_components: List[str] = []
    for comp in aibom.components:
        for lic in comp.licenses:
            lic_norm = lic.lower()
            if denied and lic_norm in denied:
                violating_components.append(comp.id)
            if allowed and allowed and lic_norm not in allowed:
                violating_components.append(comp.id)

    if not violating_components:
        return PolicyRuleResult(
            rule_id="licenses",
            passed=True,
            severity=Severity.INFO,
            message="All component licenses comply with policy.",
        )

    severity = Severity.HIGH if fail_build else Severity.MEDIUM
    return PolicyRuleResult(
        rule_id="licenses",
        passed=False,
        severity=severity,
        message="Detected components with disallowed or unknown licenses.",
        affected_components=sorted(set(violating_components)),
    )


def _eval_model_rules(policy: Dict[str, Any], aibom: AIBOM) -> Optional[PolicyRuleResult]:
    models_cfg = policy.get("models")
    if not isinstance(models_cfg, dict):
        return None

    approved = set(map(str.lower, models_cfg.get("approved", []) or []))
    denied = set(map(str.lower, models_cfg.get("denied", []) or []))
    fail_build = bool(models_cfg.get("fail_build", True))

    violating_models: List[str] = []
    for model in aibom.models:
        name = model.name.lower()
        if denied and name in denied:
            violating_models.append(model.id)
        if approved and name not in approved:
            violating_models.append(model.id)

    if not violating_models:
        return PolicyRuleResult(
            rule_id="models",
            passed=True,
            severity=Severity.INFO,
            message="All models comply with policy.",
        )

    severity = Severity.HIGH if fail_build else Severity.MEDIUM
    return PolicyRuleResult(
        rule_id="models",
        passed=False,
        severity=severity,
        message="Detected models that are not approved by policy.",
        affected_components=sorted(set(violating_models)),
    )


def _eval_risk_rules(policy: Dict[str, Any], findings: List[Finding]) -> Optional[PolicyRuleResult]:
    risk_cfg = policy.get("risk")
    if not isinstance(risk_cfg, dict):
        return None

    max_severity = risk_cfg.get("max_severity", "high").lower()
    fail_build = bool(risk_cfg.get("fail_build", True))

    severity_rank = {
        "info": 0,
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }
    threshold = severity_rank.get(max_severity, 3)

    over_threshold = [
        f
        for f in findings
        if severity_rank.get(f.severity.value, 0) > threshold
    ]

    if not over_threshold:
        return PolicyRuleResult(
            rule_id="risk",
            passed=True,
            severity=Severity.INFO,
            message="No findings exceed configured maximum severity.",
        )

    severity = Severity.HIGH if fail_build else Severity.MEDIUM
    return PolicyRuleResult(
        rule_id="risk",
        passed=False,
        severity=severity,
        message="One or more findings exceed configured maximum severity.",
        affected_components=[f.component_id for f in over_threshold if f.component_id],
    )


def _eval_ai_controls_rules(
    policy: Dict[str, Any],
    aibom: AIBOM,
    findings: List[Finding],
    analysis_results: Optional[Dict[str, Any]] = None,
) -> Optional[PolicyRuleResult]:
    """
    Evaluate AI-specific security control rules.

    Supported policy.yaml keys under ai_controls:
      no_code_execution_tools: true   — fail if PythonREPL/exec tool detected
      no_shadow_ai: true              — fail if undeclared AI SDK imports found
      mcp_trust_score_minimum: 60     — fail if any MCP server below threshold
      no_user_data_to_external_llm: true  — fail if taint confirms user→external LLM
      no_hardcoded_credentials: true  — fail if PAT-010 findings present (default True)
      require_output_validation: false — warn if PAT-011 present
    """
    cfg = policy.get("ai_controls")
    if not isinstance(cfg, dict):
        return None

    violations: List[str] = []
    results_info = analysis_results or {}

    # Rule: no_code_execution_tools
    if cfg.get("no_code_execution_tools", False):
        pattern_analysis = results_info.get("pattern_analysis")
        if pattern_analysis:
            rce_findings = [
                f for f in getattr(pattern_analysis, "findings", [])
                if getattr(f, "vulnerability_id", "") == "PAT-002"
                and not getattr(f, "dismissed_as_fp", False)
            ]
            if rce_findings:
                violations.append(
                    f"Code execution tools (PythonREPL/exec) detected in {len(rce_findings)} location(s). "
                    "Policy requires no_code_execution_tools=true."
                )

    # Rule: no_shadow_ai
    if cfg.get("no_shadow_ai", False):
        shadow_findings = [
            f for f in findings
            if "shadow" in f.id.lower() or "shadow" in f.title.lower()
        ]
        if shadow_findings:
            violations.append(
                f"Shadow AI detected: {len(shadow_findings)} undeclared AI SDK(s) used in code."
            )

    # Rule: mcp_trust_score_minimum
    min_trust = cfg.get("mcp_trust_score_minimum")
    if min_trust is not None:
        low_trust = [
            s for s in aibom.mcp_servers
            if getattr(s, "trust_score", 100) < int(min_trust)
        ]
        if low_trust:
            violations.append(
                f"{len(low_trust)} MCP server(s) below trust score threshold "
                f"{min_trust}: {[s.name for s in low_trust]}"
            )

    # Rule: no_user_data_to_external_llm
    if cfg.get("no_user_data_to_external_llm", False):
        crossfile_taint = results_info.get("crossfile_taint")
        if crossfile_taint:
            llm_paths = [
                tp for tp in getattr(crossfile_taint, "taint_paths", [])
                if tp.confirmed and tp.sink_type == "llm"
            ]
            if llm_paths:
                violations.append(
                    f"Cross-file taint analysis confirmed {len(llm_paths)} path(s) "
                    "from external user input to LLM sink."
                )

    # Rule: no_hardcoded_credentials (default True — always check)
    if cfg.get("no_hardcoded_credentials", True):
        pattern_analysis = results_info.get("pattern_analysis")
        if pattern_analysis:
            cred_findings = [
                f for f in getattr(pattern_analysis, "findings", [])
                if getattr(f, "vulnerability_id", "") == "PAT-010"
                and not getattr(f, "dismissed_as_fp", False)
            ]
            if cred_findings:
                violations.append(
                    f"Hardcoded credentials detected in {len(cred_findings)} location(s). "
                    "Never commit API keys or passwords to source code."
                )

    if not violations:
        return PolicyRuleResult(
            rule_id="ai_controls",
            passed=True,
            severity=Severity.INFO,
            message="All AI security controls pass.",
        )

    fail_build = cfg.get("fail_build", True)
    return PolicyRuleResult(
        rule_id="ai_controls",
        passed=False,
        severity=Severity.CRITICAL if fail_build else Severity.HIGH,
        message=f"AI security control violations ({len(violations)}): " + " | ".join(violations),
        affected_components=[s.id for s in aibom.mcp_servers],
    )


def evaluate_policy(
    config: PolicyConfig,
    aibom: AIBOM,
    findings: List[Finding],
    analysis_results: Optional[Dict[str, Any]] = None,
) -> PolicyReport:
    raw = config.raw
    results: List[PolicyRuleResult] = []

    lic = _eval_license_rules(raw, aibom)
    if lic:
        results.append(lic)

    mod = _eval_model_rules(raw, aibom)
    if mod:
        results.append(mod)

    risk = _eval_risk_rules(raw, findings)
    if risk:
        results.append(risk)

    ai = _eval_ai_controls_rules(raw, aibom, findings, analysis_results)
    if ai:
        results.append(ai)

    passed = all(r.passed for r in results) if results else True
    return PolicyReport(passed=passed, results=results)

