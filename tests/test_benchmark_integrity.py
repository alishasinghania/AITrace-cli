"""Scoring-harness integrity: controlled rows plus a few end-to-end checks."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from benchmarks.harness import (
    Annotation,
    ClassScore,
    score_case,
    score_reports,
    unique_finding_keys,
)


@dataclass
class FakeFinding:
    """Minimal finding used to drive the scorer without the analyzer."""

    vulnerability_id: str
    file: str
    line: Optional[int]
    source_line: Optional[int] = 1


@dataclass
class FakeFlow:
    """Minimal DataFlow used for role scoring."""

    file: str
    line: Optional[int]
    sink_arg_role: str = ""


def _ann(
    rule: str,
    cls: str,
    file: str = "app.py",
    line: int = 10,
    extra: str = "",
    case: str = "synth",
) -> Annotation:
    return Annotation(case=case, file=file, line=line, rule=rule, evidence_class=cls, extra=extra)


def _score(anns, findings, flows=None, coverage=None, case_dir: Optional[Path] = None):
    root = case_dir or Path("/tmp/aitrace-bench-synth")
    return score_case("synth", root, anns, findings, flows or [], coverage or {})


def test_known_true_positive():
    report = _score(
        [_ann("FLOW-LLM", "confirmed_taint")],
        [FakeFinding("FLOW-LLM", "app.py", 10)],
    )
    assert report.rows[0].outcome == "tp"


def test_known_false_positive_unannotated_flow():
    report = _score(
        [],
        [FakeFinding("FLOW-LLM", "app.py", 10)],
    )
    assert report.rows[0].outcome == "fp"
    assert report.rows[0].annotation["evidence_class"] == "confirmed_taint"


def test_known_false_negative_missing_finding():
    report = _score(
        [_ann("FLOW-LLM", "confirmed_taint")],
        [],
    )
    assert report.rows[0].outcome == "fn"


def test_expected_positive_with_no_analyzer_output_is_fn():
    report = _score(
        [_ann("FLOW-SQL", "confirmed_taint", file="db.py", line=4)],
        [],
    )
    outcomes = {row.outcome for row in report.rows}
    assert outcomes == {"fn"}


def test_duplicate_findings_do_not_inflate_tp():
    findings = [
        FakeFinding("FLOW-LLM", "app.py", 10),
        FakeFinding("FLOW-LLM", "app.py", 10),
    ]
    assert len(unique_finding_keys(findings, Path("/tmp/x"))) == 1
    report = _score([_ann("FLOW-LLM", "confirmed_taint")], findings)
    tps = [r for r in report.rows if r.outcome == "tp"]
    fps = [r for r in report.rows if r.outcome == "fp"]
    assert len(tps) == 1
    assert fps == []


def test_same_basename_different_directories_do_not_collide():
    anns = [
        _ann("FLOW-LLM", "confirmed_taint", file="pkg_a/app.py", line=3),
        _ann("FLOW-LLM", "absent", file="pkg_b/app.py", line=3),
    ]
    findings = [FakeFinding("FLOW-LLM", "pkg_a/app.py", 3)]
    report = _score(anns, findings)
    by_file = {row.annotation["file"]: row.outcome for row in report.rows}
    assert by_file["pkg_a/app.py"] == "tp"
    assert by_file["pkg_b/app.py"] == "tn"


def test_absolute_paths_normalize_to_case_relative(tmp_path: Path):
    sink = tmp_path / "pkg_a" / "app.py"
    sink.parent.mkdir()
    anns = [_ann("FLOW-LLM", "confirmed_taint", file="pkg_a/app.py", line=8)]
    findings = [FakeFinding("FLOW-LLM", str(sink), 8)]
    report = _score(anns, findings, case_dir=tmp_path)
    assert report.rows[0].outcome == "tp"


def test_missing_sink_line_is_explicit_fn_not_silent_match():
    report = _score(
        [_ann("FLOW-LLM", "confirmed_taint", line=10)],
        [FakeFinding("FLOW-LLM", "app.py", None)],
    )
    assert report.rows[0].outcome == "fn"
    assert "missing" in report.rows[0].detail
    extras = [r for r in report.rows if r.outcome == "fp"]
    assert extras and "missing sink line" in extras[0].detail


def test_coverage_is_not_confirmed_taint():
    report = _score(
        [_ann("unresolved_call", "coverage", line=20)],
        [],
        coverage={"unresolved_calls": {"count": 2, "samples": ["vendor.complete"]}},
    )
    assert report.rows[0].outcome == "tp"
    assert report.rows[0].annotation["evidence_class"] == "coverage"
    assert not any(r.annotation.get("evidence_class") == "confirmed_taint" for r in report.rows)


def test_structural_path_is_not_confirmed_taint():
    report = _score(
        [_ann("FLOW-LLM", "structural", line=24)],
        [],
    )
    assert report.rows[0].outcome == "tn"
    assert "no confirmed taint" in report.rows[0].detail


def test_structural_flow_is_single_fp_not_double_counted():
    report = _score(
        [_ann("FLOW-LLM", "structural", line=24)],
        [FakeFinding("FLOW-LLM", "app.py", 24)],
    )
    fps = [r for r in report.rows if r.outcome == "fp"]
    assert len(fps) == 1


def test_pattern_finding_does_not_count_as_confirmed_taint():
    report = _score(
        [
            _ann("PAT-003", "pattern", line=30),
            _ann("FLOW-SQL", "absent", line=30),
        ],
        [FakeFinding("PAT-003", "app.py", 30)],
    )
    by_cls = {r.annotation["evidence_class"]: r.outcome for r in report.rows}
    assert by_cls["pattern"] == "tp"
    assert by_cls["absent"] == "tn"


def test_parameterized_sql_is_not_injection():
    report = _score(
        [_ann("FLOW-SQL", "absent", line=25)],
        [],
        flows=[FakeFlow("app.py", 25, sink_arg_role="query")],
    )
    assert report.rows[0].outcome == "tn"


def test_http_body_is_not_url_control_taint():
    report = _score(
        [_ann("http", "dataflow_role", line=19, extra="role=body")],
        [],
        flows=[FakeFlow("app.py", 19, sink_arg_role="body")],
    )
    assert report.rows[0].outcome == "tp"
    assert report.rows[0].detail == "DataFlow role=body without FLOW-HTTP"


def test_http_body_plus_flow_http_is_not_url_success():
    report = _score(
        [_ann("http", "dataflow_role", line=19, extra="role=body")],
        [FakeFinding("FLOW-HTTP", "app.py", 19)],
        flows=[FakeFlow("app.py", 19, sink_arg_role="body")],
    )
    assert report.rows[0].outcome == "fn"
    assert "FLOW-HTTP" in report.rows[0].detail


def test_undefined_precision_and_recall_are_none():
    empty = ClassScore()
    assert empty.precision() is None
    assert empty.recall() is None
    only_tn = ClassScore(tn=3)
    assert only_tn.precision() is None
    assert only_tn.recall() is None


def test_sensitivity_recall_drops_when_expected_finding_removed():
    anns = [_ann("FLOW-LLM", "confirmed_taint")]
    full = _score(anns, [FakeFinding("FLOW-LLM", "app.py", 10)])
    dropped = _score(anns, [])
    full_s = score_reports([full])["confirmed_taint"]
    drop_s = score_reports([dropped])["confirmed_taint"]
    assert full_s.recall() == 1.0
    assert drop_s.recall() == 0.0
    assert drop_s.recall() < full_s.recall()


def test_sensitivity_precision_drops_when_unexpected_finding_added():
    anns = [_ann("FLOW-LLM", "confirmed_taint", line=10)]
    full = _score(anns, [FakeFinding("FLOW-LLM", "app.py", 10)])
    noisy = _score(
        anns,
        [
            FakeFinding("FLOW-LLM", "app.py", 10),
            FakeFinding("FLOW-LLM", "other.py", 99),
        ],
    )
    full_s = score_reports([full])["confirmed_taint"]
    noisy_s = score_reports([noisy])["confirmed_taint"]
    assert full_s.precision() == 1.0
    assert noisy_s.precision() == 0.5
    assert noisy_s.precision() < full_s.precision()


def test_end_to_end_basename_collision(tmp_path: Path):
    """Analyzer paths are case-relative; two app.py files must not share a TP."""
    from benchmarks import harness as harness_mod

    case = tmp_path / "collision"
    (case / "pkg_a").mkdir(parents=True)
    (case / "pkg_b").mkdir()
    (case / "pkg_a" / "app.py").write_text(
        "from flask import request\n"
        "def a():\n"
        "    llm.invoke(request.json['m'])  # gt:FLOW-LLM:confirmed_taint\n",
        encoding="utf-8",
    )
    (case / "pkg_b" / "app.py").write_text(
        "def b():\n"
        "    llm.invoke('hello')  # gt:FLOW-LLM:absent\n",
        encoding="utf-8",
    )
    report = harness_mod._match_case("collision", case)
    by_file = {row.annotation["file"]: row for row in report.rows if row.annotation.get("rule") == "FLOW-LLM"}
    assert "pkg_a/app.py" in by_file
    assert "pkg_b/app.py" in by_file
    assert by_file["pkg_a/app.py"].outcome in {"tp", "fn"}
    assert by_file["pkg_b/app.py"].outcome in {"tn", "fp"}
    if by_file["pkg_a/app.py"].outcome == "tp":
        assert by_file["pkg_b/app.py"].outcome == "tn"


def test_end_to_end_parameterized_sql_and_http_roles():
    from benchmarks.harness import DEVELOPMENT_ROOT, _match_case

    sql = _match_case("sql", DEVELOPMENT_ROOT / "sql")
    absent = [
        r
        for r in sql.rows
        if r.annotation.get("evidence_class") == "absent" and r.annotation.get("rule") == "FLOW-SQL"
    ]
    assert absent
    assert all(r.outcome == "tn" for r in absent)

    http = _match_case("http", DEVELOPMENT_ROOT / "http")
    roles = [r for r in http.rows if r.annotation.get("evidence_class") == "dataflow_role"]
    assert roles
    assert all(r.outcome == "tp" for r in roles)
    assert all("without FLOW-HTTP" in r.detail for r in roles)
