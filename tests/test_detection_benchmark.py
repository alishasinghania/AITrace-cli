"""Run the synthetic detection benchmark and assert dataset separation."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from benchmarks.harness import run_all


def test_benchmark_reports_datasets_separately():
    report = run_all()
    assert report["combined_score"] is None
    datasets = report["datasets"]
    assert "development" in datasets
    assert "locked_eval" in datasets
    assert datasets["development"]["dataset"] == "development"
    assert datasets["locked_eval"]["dataset"] == "locked_eval"
    assert datasets["development"]["independent"] is False
    assert datasets["locked_eval"]["independent"] is False
    assert "Phase 6" in datasets["locked_eval"]["notes"]


def test_development_confirmed_taint_metrics():
    """Regression check on development fixtures only — not production accuracy."""
    report = run_all()
    confirmed = report["datasets"]["development"]["by_class"].get("confirmed_taint") or {}
    assert confirmed.get("fn", 1) == 0, report["datasets"]["development"]["cases"]
    assert confirmed.get("fp", 1) == 0, report["datasets"]["development"]["cases"]
    assert confirmed.get("tp", 0) >= 1
    assert confirmed.get("precision") == 1.0
    assert confirmed.get("recall") == 1.0


def test_development_absent_sql_coverage_classes():
    report = run_all()
    dev = report["datasets"]["development"]["by_class"]
    absent = dev.get("absent") or {}
    assert absent.get("fp", 1) == 0
    sql = dev.get("sql_interpolation") or {}
    assert sql.get("fn", 1) == 0
    assert sql.get("tp", 0) >= 1
    rce = dev.get("rce_execution") or {}
    assert rce.get("fn", 1) == 0
    cov = dev.get("coverage") or {}
    assert cov.get("tp", 0) >= 1


def test_locked_eval_is_scored_but_not_merged_into_development():
    report = run_all()
    locked = report["datasets"]["locked_eval"]
    cases = {c["case"] for c in locked["cases"]}
    assert "held_out" in cases
    dev_cases = {c["case"] for c in report["datasets"]["development"]["cases"]}
    assert "held_out" not in dev_cases
    assert "llm" in dev_cases


def test_undefined_metrics_serialized_as_null_not_perfect():
    report = run_all()
    dumped = json.dumps(report)
    assert "undefined" in dumped
    for name, payload in report["datasets"].items():
        for cls, stats in payload["by_class"].items():
            if stats["tp"] + stats["fp"] == 0:
                assert stats["precision"] is None, (name, cls, stats)
                assert stats["precision_display"] == "undefined"
            if stats["tp"] + stats["fn"] == 0:
                assert stats["recall"] is None, (name, cls, stats)
                assert stats["recall_display"] == "undefined"


def test_benchmark_writes_machine_readable_shape():
    report = run_all()
    assert "matching_policy" in report
    assert report["identity"].startswith("rule +")
    dumped = json.dumps(report)
    assert "FLOW-LLM" in dumped or report["datasets"]["development"]["by_class"]
