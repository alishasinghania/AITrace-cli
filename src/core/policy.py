from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from .models import AIBOM, Finding, PolicyReport, PolicyRuleResult, Severity


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


def evaluate_policy(config: PolicyConfig, aibom: AIBOM, findings: List[Finding]) -> PolicyReport:
    raw = config.raw
    results: List[PolicyRuleResult] = []

    for fn in (_eval_license_rules, _eval_model_rules, _eval_risk_rules):
        result = fn(raw, aibom if fn is not _eval_risk_rules else findings)  # type: ignore[arg-type]
        if result:
            results.append(result)

    passed = all(r.passed for r in results) if results else True
    return PolicyReport(passed=passed, results=results)

