"""Enterprise HTML report: light theme, inventory, per-finding taint, offline."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from core.engine import AITraceEngine
from core.exporters.html_report import to_html_report


def _report(tmp_path: Path) -> str:
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "@app.post('/chat')\n"
        "def chat():\n"
        "    llm.invoke(request.json['message'])\n",
        encoding="utf-8",
    )
    return to_html_report(AITraceEngine(tmp_path).analyze(), tmp_path)


def test_light_theme_and_no_new_cdn(tmp_path: Path):
    html = _report(tmp_path)
    assert "--bg:#f4f6f8" in html
    assert "background:var(--bg)" in html
    assert "theme:'neutral'" in html
    assert "fonts.googleapis" not in html
    assert "unpkg.com" not in html
    assert "cytoscape" not in html.lower()
    assert "cdn.jsdelivr.net/npm/mermaid" in html


def test_howto_and_nav_present(tmp_path: Path):
    html = _report(tmp_path)
    assert "How to read this" in html
    assert "aria-label='Report sections'" in html
    assert "href='#findings'" in html
    assert "href='#taint-flow-graph'" in html
    assert "id='ai-components'" in html
    assert "id='ai-overview'" in html
    assert "AI Application Overview" in html
    assert "AI Components" in html


def test_taint_defaults_to_one_flow(tmp_path: Path):
    html = _report(tmp_path)
    assert "Taint paths" in html
    assert "data-taint-flow='taint'" in html
    assert " selected>" in html
    assert "taint-flow-panel is-active" in html
    assert "taint-story" in html
    assert "taint-path-table" in html
    assert "Each box is a location" in html
    assert "All flows" not in html
    assert "aitrace-taint-data" in html
    assert "aitrace-arch-data" in html
    assert "graph-fallback" in html


def test_findings_preserve_provenance(tmp_path: Path):
    html = _report(tmp_path)
    assert "Security Findings" in html
    assert "confidence:" in html or "taint:" in html or "path confirmed" in html
    assert "Show confirmed path" in html or "FLOW-LLM" in html
    assert "AI Application Overview" in html


def test_graph_labels_are_centered_under_nodes(tmp_path: Path):
    """Node captions sit under the circle at native SVG size so they cannot collide."""
    html = _report(tmp_path)
    assert "text-anchor='middle'" in html
    assert "p.x+16" not in html
    assert "labelLines" in html
    assert "COL_GAP=200" in html
    assert "height:560px" not in html
    assert 'removeAttribute("viewBox")' in html
    assert "svg.style.width" in html


def test_component_inventory_not_duplicate_graph(tmp_path: Path):
    html = _report(tmp_path)
    assert html.count("AI Application Overview") == 1
    assert "AI Components" in html
    assert "data-overview-tab='inv'" in html
    assert "Package inventory is under AI Components" in html or "How to read this" in html
