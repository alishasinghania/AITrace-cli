"""Run synthetic detection cases and score them against source annotations.

This module must not be imported by the scan engine.
"""

from __future__ import annotations

import json
import re
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

ROOT = Path(__file__).resolve().parent
CASES = ROOT / "cases"
DEVELOPMENT_ROOT = CASES / "development"
LOCKED_EVAL_ROOT = CASES / "locked_eval"

# Annotations:  # gt:RULE:class   optional role=body
_GT = re.compile(
    r"#\s*gt:(?P<rule>[A-Za-z0-9_-]+):(?P<cls>[A-Za-z0-9_]+)"
    r"(?:\|(?P<extra>[A-Za-z0-9_=,-]+))?"
)

# Evidence-class aliases. These do not promote a weaker class into a stronger one.
# confirmed_taint still requires the exact FLOW-* rule named on the annotation.
RCE_EXECUTION_RULES: Tuple[str, ...] = ("FLOW-RCE", "PAT-025", "PAT-004", "PAT-002")
SQL_INTERPOLATION_RULES: Tuple[str, ...] = ("FLOW-SQL", "PAT-003")

MATCHING_POLICY = (
    "Identity is (rule, case-relative POSIX path, sink line). "
    "Confirmed-taint TPs are FLOW-* findings at the annotated sink path and line. "
    "sql_interpolation accepts FLOW-SQL or PAT-003 but not both (dedup miss). "
    "rce_execution accepts FLOW-RCE or PAT-025/004/002 at that sink; that is a "
    "class-level alias, not equivalence of evidence strength. "
    "absent annotations score unexpected named rules as FP. "
    "Unannotated FLOW-* findings are extra confirmed_taint FPs. "
    "Architecture, BFS structural reachability, and coverage are not confirmed taint. "
    "Duplicate findings with the same identity count once. "
    "Precision = tp/(tp+fp); recall = tp/(tp+fn); undefined when the denominator is 0."
)

DATASET_META: Dict[str, Dict[str, Any]] = {
    "development": {
        "role": "Cases used during implementation and debugging.",
        "independent": False,
        "notes": (
            "Scores on this dataset are regression checks for synthetic fixtures, "
            "not production accuracy."
        ),
    },
    "locked_eval": {
        "role": "Cases isolated from the development tree and not used to tune Phase 7 scoring.",
        "independent": False,
        "notes": (
            "These files (formerly cases/held_out/) were authored and inspected during "
            "Phase 6. They are a locked evaluation split, not a genuinely independent "
            "third-party application. See INDEPENDENT_EVALUATION.md to add one later."
        ),
    },
}


@dataclass
class Annotation:
    """One ground-truth expectation at a source line."""

    case: str
    file: str
    line: int
    rule: str
    evidence_class: str
    extra: str = ""
    rationale: str = ""


@dataclass
class MatchRow:
    """Result of comparing one annotation or extra finding to analyzer output."""

    annotation: Dict[str, Any]
    outcome: str  # tp, tn, fn, fp
    detail: str = ""


@dataclass
class ClassScore:
    """Counts for one evidence class."""

    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    def precision(self) -> Optional[float]:
        """tp / (tp + fp), or None when that denominator is zero."""
        den = self.tp + self.fp
        return (self.tp / den) if den else None

    def recall(self) -> Optional[float]:
        """tp / (tp + fn), or None when that denominator is zero."""
        den = self.tp + self.fn
        return (self.tp / den) if den else None


@dataclass
class CaseReport:
    """Per-case score plus leftover findings."""

    case: str
    rows: List[MatchRow] = field(default_factory=list)
    extra_confirmed: List[str] = field(default_factory=list)
    lineage_notes: List[str] = field(default_factory=list)
    harness_issues: List[str] = field(default_factory=list)


FindingKey = Tuple[str, str, Optional[int]]


def parse_annotations(case_dir: Path, case: str) -> List[Annotation]:
    """Read `# gt:` markers from Python files in a case directory."""
    out: List[Annotation] = []
    for path in sorted(case_dir.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        rel = _posix_rel(path, case_dir)
        for i, line in enumerate(text.splitlines(), 1):
            for m in _GT.finditer(line):
                out.append(
                    Annotation(
                        case=case,
                        file=rel,
                        line=i,
                        rule=m.group("rule"),
                        evidence_class=m.group("cls"),
                        extra=m.group("extra") or "",
                        rationale=m.group(0),
                    )
                )
    return out


def _posix_rel(path: Path, root: Path) -> str:
    """Return a POSIX path relative to root."""
    return str(path.resolve().relative_to(root.resolve())).replace("\\", "/")


def normalize_path(file: str, case_dir: Path) -> str:
    """Map an analyzer file path onto a case-relative POSIX path.

    Absolute paths under the case directory are relativized. Other absolute
    paths keep their basename only as a last resort and are therefore *not*
    used as a collision-prone default identity.
    """
    raw = str(file or "").replace("\\", "/")
    if not raw:
        return ""
    case_res = case_dir.resolve()
    p = Path(raw)
    try:
        if p.is_absolute():
            return str(p.resolve().relative_to(case_res)).replace("\\", "/")
    except (ValueError, OSError):
        pass
    case_s = str(case_res).replace("\\", "/")
    if raw.startswith(case_s.rstrip("/") + "/"):
        return raw[len(case_s.rstrip("/")) + 1 :]
    if not p.is_absolute():
        return raw.lstrip("./")
    return p.name


def _sink_line(value: Any) -> Optional[int]:
    """Normalize a sink line; None means the analyzer omitted it."""
    if value is None or value == "":
        return None
    try:
        n = int(value)
    except (TypeError, ValueError):
        return None
    return n if n > 0 else None


def _finding_identity(finding: Any, case_dir: Path) -> FindingKey:
    """Identity used for matching: rule, case-relative path, sink line."""
    vid = str(getattr(finding, "vulnerability_id", None) or getattr(finding, "id", "") or "")
    path = normalize_path(str(getattr(finding, "file", "") or ""), case_dir)
    return (vid, path, _sink_line(getattr(finding, "line", None)))


def unique_finding_keys(findings: Sequence[Any], case_dir: Path) -> Set[FindingKey]:
    """Deduplicate analyzer rows that share rule, path, and sink line."""
    return {_finding_identity(f, case_dir) for f in findings}


def _promote(root: Path):
    """Same promotion pipeline as FLOW-* unit tests (not HTML)."""
    src = str(ROOT.parent / "src")
    if src not in sys.path:
        sys.path.insert(0, src)
    from core.analyzers.crossfile_taint import analyze_crossfile_taint
    from core.analyzers.dataflow_analyzer import analyze_dataflows
    from core.analyzers.pattern_analyzer import analyze_patterns
    from core.exporters.finding_contract import coverage_from_analysis

    flows = analyze_dataflows(root)
    patterns = analyze_patterns(root)
    xt = analyze_crossfile_taint(root, patterns.findings, data_flows=flows.data_flows)
    return patterns.findings, flows, xt, coverage_from_analysis(flows)


def _extra_field(ann: Annotation, key: str) -> str:
    for part in (ann.extra or "").split(","):
        if part.startswith(f"{key}="):
            return part.split("=", 1)[1]
    return ""


def score_case(
    case: str,
    case_dir: Path,
    annotations: Sequence[Annotation],
    findings: Sequence[Any],
    data_flows: Sequence[Any],
    coverage: Optional[Dict[str, Any]] = None,
) -> CaseReport:
    """Score analyzer output against annotations without running the engine.

    Used by the live harness and by integrity tests that inject synthetic rows.
    """
    coverage = coverage or {}
    keys = unique_finding_keys(findings, case_dir)
    report = CaseReport(case=case)
    claimed: Set[FindingKey] = set()
    seen_ann: Set[Tuple[str, str, int, str, str]] = set()

    def has_rule(rule: str, rel_file: str, line: Optional[int]) -> bool:
        return (rule, rel_file, line) in keys

    def dataflow_at(rel_file: str, line: int) -> List[Any]:
        hits = []
        for df in data_flows:
            df_file = normalize_path(str(getattr(df, "file", "") or ""), case_dir)
            if df_file == rel_file and _sink_line(getattr(df, "line", None)) == line:
                hits.append(df)
        return hits

    def claim(rule: str, rel_file: str, line: Optional[int]) -> None:
        claimed.add((rule, rel_file, line))

    for finding in findings:
        vid, path, line = _finding_identity(finding, case_dir)
        src_line = getattr(finding, "source_line", None)
        if str(vid).startswith("FLOW-") and line is None:
            report.lineage_notes.append(f"{vid} {path}: missing sink line")
        if str(vid).startswith("FLOW-") and src_line in (None, "", 0):
            report.lineage_notes.append(f"{vid} {path}:{line}: missing source_line")

    for ann in annotations:
        rec = asdict(ann)
        cls = ann.evidence_class
        ident = (ann.rule, ann.file, ann.line, cls, ann.extra)
        if ident in seen_ann:
            report.harness_issues.append(
                f"duplicate annotation {ann.rule} {ann.file}:{ann.line} class={cls}"
            )
            report.rows.append(MatchRow(rec, "fn", "duplicate annotation; finding already considered"))
            continue
        seen_ann.add(ident)

        if cls == "confirmed_taint":
            key: FindingKey = (ann.rule, ann.file, ann.line)
            if key in claimed:
                report.rows.append(MatchRow(rec, "fn", "finding already matched to another annotation"))
            elif has_rule(ann.rule, ann.file, ann.line):
                report.rows.append(MatchRow(rec, "tp", "FLOW finding at sink"))
                claim(ann.rule, ann.file, ann.line)
            else:
                miss = "missing FLOW finding"
                if any(r == ann.rule and p == ann.file and ln is None for r, p, ln in keys):
                    miss = "FLOW finding present but sink line is missing"
                elif any(r == ann.rule and p == ann.file for r, p, ln in keys):
                    miss = "FLOW finding present but sink line does not match annotation"
                report.rows.append(MatchRow(rec, "fn", miss))
        elif cls == "rce_execution":
            hits = [rid for rid in RCE_EXECUTION_RULES if has_rule(rid, ann.file, ann.line)]
            unused = [rid for rid in hits if (rid, ann.file, ann.line) not in claimed]
            if unused:
                report.rows.append(
                    MatchRow(
                        rec,
                        "tp",
                        "+".join(unused) + " (alias class; not confirmed_taint)",
                    )
                )
                for rid in unused:
                    claim(rid, ann.file, ann.line)
            elif hits:
                report.rows.append(MatchRow(rec, "fn", "finding already matched to another annotation"))
            else:
                report.rows.append(MatchRow(rec, "fn", "no RCE finding"))
        elif cls == "sql_interpolation":
            sql = has_rule("FLOW-SQL", ann.file, ann.line)
            pat = has_rule("PAT-003", ann.file, ann.line)
            if sql and pat:
                report.rows.append(MatchRow(rec, "fn", "dedup failure: both FLOW-SQL and PAT-003"))
                claim("FLOW-SQL", ann.file, ann.line)
                claim("PAT-003", ann.file, ann.line)
            elif sql or pat:
                report.rows.append(MatchRow(rec, "tp", "FLOW-SQL or PAT-003 (alias class)"))
                if sql:
                    claim("FLOW-SQL", ann.file, ann.line)
                if pat:
                    claim("PAT-003", ann.file, ann.line)
            else:
                report.rows.append(MatchRow(rec, "fn", "no SQL interpolation finding"))
        elif cls == "pattern":
            key = (ann.rule, ann.file, ann.line)
            if key in claimed:
                report.rows.append(MatchRow(rec, "fn", "finding already matched to another annotation"))
            elif has_rule(ann.rule, ann.file, ann.line):
                report.rows.append(MatchRow(rec, "tp", "pattern finding"))
                claim(ann.rule, ann.file, ann.line)
            else:
                report.rows.append(MatchRow(rec, "fn", "missing pattern"))
        elif cls == "absent":
            if has_rule(ann.rule, ann.file, ann.line):
                report.rows.append(MatchRow(rec, "fp", f"unexpected {ann.rule}"))
                claim(ann.rule, ann.file, ann.line)
            else:
                report.rows.append(MatchRow(rec, "tn", f"no {ann.rule}"))
        elif cls == "dataflow_role":
            role = _extra_field(ann, "role")
            dfs = dataflow_at(ann.file, ann.line)
            has_role = any((getattr(df, "sink_arg_role", "") or "") == role for df in dfs)
            has_http_finding = has_rule("FLOW-HTTP", ann.file, ann.line)
            if has_http_finding:
                claim("FLOW-HTTP", ann.file, ann.line)
            if has_role and not has_http_finding:
                report.rows.append(MatchRow(rec, "tp", f"DataFlow role={role} without FLOW-HTTP"))
            else:
                why = []
                if not has_role:
                    why.append("missing role DataFlow")
                if has_http_finding:
                    why.append("unexpected FLOW-HTTP")
                report.rows.append(MatchRow(rec, "fn", "; ".join(why) or "role mismatch"))
        elif cls == "coverage":
            bucket: Dict[str, Any] = {}
            if ann.rule == "unresolved_call":
                bucket = coverage.get("unresolved_calls") or {}
            elif ann.rule == "unsupported_call_form":
                bucket = coverage.get("unsupported_call_forms") or {}
            else:
                bucket = coverage.get(ann.rule) or {}
            ok = int(bucket.get("count") or 0) >= 1
            if ok:
                report.rows.append(MatchRow(rec, "tp", "coverage recorded (not a finding)"))
            else:
                report.rows.append(MatchRow(rec, "fn", "coverage not recorded"))
        elif cls == "structural":
            confirmed = [
                k
                for k in keys
                if str(k[0]).startswith("FLOW-")
                and k[1] == ann.file
                and k[2] == ann.line
            ]
            if confirmed:
                report.rows.append(MatchRow(rec, "fp", "FLOW finding on structural-only sink"))
                for k in confirmed:
                    claimed.add(k)
            else:
                report.rows.append(MatchRow(rec, "tn", "no confirmed taint at structural sink"))
        else:
            report.rows.append(MatchRow(rec, "fn", f"unknown evidence class {cls}"))

    scored_flow = {k for k in claimed if str(k[0]).startswith("FLOW-")}
    for vid, path, line in sorted(keys, key=lambda x: (x[0], x[1], x[2] is None, x[2] or 0)):
        if not str(vid).startswith("FLOW-"):
            continue
        if (vid, path, line) in scored_flow:
            continue
        detail = "FLOW finding without ground-truth annotation"
        if line is None:
            detail = "FLOW finding with missing sink line and no annotation"
        report.extra_confirmed.append(f"{vid} {path}:{line}")
        report.rows.append(
            MatchRow(
                {
                    "case": case,
                    "file": path,
                    "line": line,
                    "rule": vid,
                    "evidence_class": "confirmed_taint",
                    "extra": "",
                    "rationale": "unannotated FLOW",
                },
                "fp",
                detail,
            )
        )
    return report


def _match_case(case: str, case_dir: Path) -> CaseReport:
    """Run analyzers on a case directory and score against `# gt:` markers."""
    anns = parse_annotations(case_dir, case)
    findings, flows, _xt, coverage = _promote(case_dir)
    return score_case(case, case_dir, anns, findings, flows.data_flows, coverage)


def score_reports(reports: Iterable[CaseReport]) -> Dict[str, ClassScore]:
    """Aggregate TP/FP/FN/TN by evidence class."""
    by: Dict[str, ClassScore] = defaultdict(ClassScore)
    for rep in reports:
        for row in rep.rows:
            cls = row.annotation.get("evidence_class") or "unknown"
            bucket = by[cls]
            if row.outcome == "tp":
                bucket.tp += 1
            elif row.outcome == "fp":
                bucket.fp += 1
            elif row.outcome == "fn":
                bucket.fn += 1
            elif row.outcome == "tn":
                bucket.tn += 1
    return dict(by)


def _class_payload(scores: Dict[str, ClassScore]) -> Dict[str, Any]:
    payload: Dict[str, Any] = {}
    for name, s in scores.items():
        prec = s.precision()
        rec = s.recall()
        payload[name] = {
            "tp": s.tp,
            "fp": s.fp,
            "fn": s.fn,
            "tn": s.tn,
            "precision": prec,
            "recall": rec,
            "precision_display": "undefined" if prec is None else prec,
            "recall_display": "undefined" if rec is None else rec,
            "denominators": {
                "precision": "tp / (tp + fp); undefined when tp+fp == 0",
                "recall": "tp / (tp + fn); undefined when tp+fn == 0",
            },
        }
    return payload


def _dataset_payload(name: str, reports: List[CaseReport]) -> Dict[str, Any]:
    meta = DATASET_META.get(name, {})
    scores = score_reports(reports)
    return {
        "dataset": name,
        "independent": bool(meta.get("independent")),
        "role": meta.get("role", ""),
        "notes": meta.get("notes", ""),
        "matching_policy": MATCHING_POLICY,
        "aliases": {
            "sql_interpolation": {
                "accepts": list(SQL_INTERPOLATION_RULES),
                "both_at_same_sink": "fn (dedup miss)",
                "not_equivalent_to": "confirmed_taint",
            },
            "rce_execution": {
                "accepts": list(RCE_EXECUTION_RULES),
                "not_equivalent_to": "confirmed_taint",
            },
        },
        "cases": [
            {
                "case": r.case,
                "rows": [
                    {"outcome": row.outcome, "detail": row.detail, **row.annotation}
                    for row in r.rows
                ],
                "extra_confirmed": r.extra_confirmed,
                "lineage_notes": r.lineage_notes,
                "harness_issues": r.harness_issues,
            }
            for r in reports
        ],
        "by_class": _class_payload(scores),
    }


def run_dataset(name: str, cases_dir: Path) -> Dict[str, Any]:
    """Score every case directory under one dataset root."""
    reports: List[CaseReport] = []
    if cases_dir.is_dir():
        for case_dir in sorted(p for p in cases_dir.iterdir() if p.is_dir()):
            reports.append(_match_case(case_dir.name, case_dir))
    return _dataset_payload(name, reports)


def run_all(cases_dir: Path = CASES) -> Dict[str, Any]:
    """Score development and locked-evaluation datasets separately.

    ``cases_dir`` remains accepted for tests that inject a temporary tree
    containing ``development/`` and/or ``locked_eval/`` children. A flat
    directory of case folders is treated as development-only.
    """
    dev_root = cases_dir / "development"
    lock_root = cases_dir / "locked_eval"
    if not dev_root.is_dir() and not lock_root.is_dir():
        development = _dataset_payload(
            "development",
            [_match_case(p.name, p) for p in sorted(cases_dir.iterdir()) if p.is_dir()],
        )
        locked = _dataset_payload("locked_eval", [])
    else:
        development = run_dataset("development", dev_root)
        locked = run_dataset("locked_eval", lock_root)
    return {
        "matching_policy": MATCHING_POLICY,
        "identity": "rule + case-relative POSIX path + sink line",
        "datasets": {
            "development": development,
            "locked_eval": locked,
        },
        "combined_score": None,
        "combined_score_reason": (
            "Development and locked-evaluation results are not merged. "
            "A combined precision/recall would hide dataset identity."
        ),
    }


def _print_dataset(name: str, payload: Dict[str, Any]) -> None:
    """Write one dataset block to stdout."""
    print(f"== dataset: {name} ==")
    print(f"independent: {payload.get('independent')}")
    print(payload.get("notes") or payload.get("role") or "")
    for cls, stats in (payload.get("by_class") or {}).items():
        print(
            f"  {cls}: tp={stats['tp']} fp={stats['fp']} fn={stats['fn']} tn={stats['tn']} "
            f"precision={stats['precision_display']} recall={stats['recall_display']}"
        )


def main() -> None:
    """Write last_report.json next to this harness."""
    payload = run_all()
    out = ROOT / "last_report.json"
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    for name in ("development", "locked_eval"):
        _print_dataset(name, payload["datasets"][name])
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
