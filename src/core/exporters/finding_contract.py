"""Canonical finding identity, counts, and serialization for all outputs.

Finding count policy
--------------------
``finding_count`` is the number of unique ``Finding`` objects in the engine
collection (``AnalysisResult.findings``). Inventory/discovery records are
included. Multiple evidence hops or DataFlow rows on one finding do not
increase the count. Distinct sinks (rule id + sink file + sink line) remain
distinct findings.

``security_finding_count`` excludes inventory/discovery records (for example
"dependency discovered", "MCP server discovered", "LLM inference detected").
CLI and HTML Security Findings use this subset and must label it as such.

JSON ``findings`` lists every engine finding, including SEMANTIC and inventory
rows (inventory rows have ``scope=inventory``). Markdown may present pattern
and semantic rows in dedicated sections; that is a presentation difference,
not a second identity space.
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Dict, List, Optional, Sequence, Tuple

FINDING_COUNT_SCOPE = (
    "Unique Finding objects in the engine collection, including inventory "
    "and semantic records. One finding with several evidence paths counts once."
)

SECURITY_FINDING_COUNT_SCOPE = (
    "Engine findings excluding inventory/discovery records. Used by CLI and "
    "HTML Security Findings."
)

_DEFAULT_COVERAGE_NOTES = [
    "Unresolved and unsupported calls are coverage limitations, not findings.",
    "incomplete is true only when iteration or context caps truncated the worklist.",
    "Absence of truncation does not mean every construct was analyzed.",
]


def is_inventory_finding(finding: Any) -> bool:
    """True for inventory / discovery items — not security risks."""
    title = (getattr(finding, "title", "") or "").strip()
    lower = title.lower()
    if lower.endswith("dependency discovered"):
        return True
    if lower.startswith("mcp server package:"):
        return True
    if lower.startswith("mcp server discovered"):
        return True
    if lower.startswith("ai agent pattern detected"):
        return True
    if lower.startswith("llm inference detected"):
        return True
    if lower in ("model binary discovered", "model configuration discovered"):
        return True
    if lower.startswith("model binary discovered:") or lower.startswith(
        "model configuration discovered:"
    ):
        return True
    return False


def filter_security_findings(findings: Sequence[Any]) -> List[Any]:
    """Return findings that belong in the Security Findings view."""
    return [f for f in findings if not is_inventory_finding(f)]


def honest_line(line: Any) -> Optional[int]:
    """Return a 1-based line number, or None when unavailable (never guess)."""
    if line is None:
        return None
    try:
        n = int(line)
    except (TypeError, ValueError):
        return None
    if n <= 0:
        return None
    return n


def sink_location(finding: Any) -> Tuple[Optional[str], Optional[int]]:
    """Sink file and line from evidence, then metadata."""
    md = getattr(finding, "metadata", None) or {}
    if not isinstance(md, dict):
        md = {}
    ev = getattr(finding, "evidence", None) or []
    file = None
    line = None
    if ev:
        file = getattr(ev[0], "file", None)
        line = getattr(ev[0], "line", None)
    file = md.get("sink_file") or file
    if md.get("sink_line") is not None:
        line = md.get("sink_line")
    return (file or None, honest_line(line))


def serialize_finding(finding: Any) -> Dict[str, Any]:
    """Machine-readable finding used by JSON and contract tests."""
    md = getattr(finding, "metadata", None) or {}
    if not isinstance(md, dict):
        md = {}
    sink_file, sink_line = sink_location(finding)
    cat = getattr(finding, "category", None)
    sev = getattr(finding, "severity", None)
    return {
        "id": getattr(finding, "id", ""),
        "title": getattr(finding, "title", ""),
        "category": cat.value if hasattr(cat, "value") else str(cat or ""),
        "severity": sev.value if hasattr(sev, "value") else str(sev or ""),
        "description": getattr(finding, "description", ""),
        "file": sink_file,
        "line": sink_line,
        "sink_file": sink_file,
        "sink_line": sink_line,
        "source_file": (md.get("source_file") or None) or None,
        "source_line": honest_line(md.get("source_line")),
        "taint_kind": md.get("taint_kind") or "",
        "sink_arg_role": md.get("sink_arg_role") or "",
        "confidence": md.get("confidence") or "",
        "confirmed_by_taint": bool(md.get("confirmed_by_taint")),
        "scope": "inventory" if is_inventory_finding(finding) else "security",
        "tags": list(getattr(finding, "tags", None) or []),
    }


def summary_counts(findings: Sequence[Any]) -> Dict[str, Any]:
    """Counters that must match the serialized findings array."""
    rows = list(findings or [])
    security = filter_security_findings(rows)
    cats: Counter[str] = Counter()
    for f in rows:
        cat = getattr(f, "category", None)
        cats[cat.value if hasattr(cat, "value") else str(cat or "unknown")] += 1
    return {
        "finding_count": len(rows),
        "finding_count_scope": FINDING_COUNT_SCOPE,
        "security_finding_count": len(security),
        "security_finding_count_scope": SECURITY_FINDING_COUNT_SCOPE,
        "by_category": dict(cats),
    }


def empty_coverage() -> Dict[str, Any]:
    """Bounded coverage metadata independent of security findings."""
    return {
        "unresolved_calls": {"count": 0, "samples": []},
        "unsupported_call_forms": {"count": 0, "samples": []},
        "truncated": {"incomplete": False, "reasons": []},
        "notes": list(_DEFAULT_COVERAGE_NOTES),
    }


def coverage_from_analysis(dataflow_analysis: Any) -> Dict[str, Any]:
    """JSON coverage object; never treats unresolved calls as findings."""
    out = empty_coverage()
    if dataflow_analysis is None:
        return out
    raw = getattr(dataflow_analysis, "coverage", None) or {}
    if isinstance(raw, dict):
        for key in ("unresolved_calls", "unsupported_call_forms"):
            bucket = raw.get(key) or {}
            out[key] = {
                "count": int(bucket.get("count", 0) or 0),
                "samples": list(bucket.get("samples") or [])[:8],
            }
        if raw.get("notes"):
            out["notes"] = list(raw["notes"])
    out["truncated"] = {
        "incomplete": bool(getattr(dataflow_analysis, "incomplete", False)),
        "reasons": list(getattr(dataflow_analysis, "incomplete_reasons", None) or []),
    }
    return out
