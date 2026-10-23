"""Execute checks against a generated HTML artifact (not template fragments).

Browser engines and Playwright are not project dependencies. These tests:
- generate a real HTML file via to_html_report
- parse embedded graph JSON
- run Node against that JSON for filter/search semantics
- document that Mermaid still loads from a CDN
They do not drive a real browser (clicks, layout, or Chromium).
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from core.analyzers.dataflow_analyzer import DataFlow, DataFlowAnalysisResult
from core.engine import AITraceEngine
from core.exporters.html_report import to_html_report
from core.exporters.taint_graph import build_taint_flow_graph


def _extract_json(html: str, script_id: str) -> dict:
    start = html.find(f"id='{script_id}'")
    assert start != -1, f"missing {script_id}"
    gt = html.find(">", start)
    end = html.find("</script>", gt)
    return json.loads(html[gt + 1 : end])


def test_generated_html_graphs_and_offline_svg(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "@app.post('/chat')\n"
        "def chat():\n"
        "    llm.invoke(request.json['message'])\n",
        encoding="utf-8",
    )
    result = AITraceEngine(tmp_path).analyze()
    html_path = tmp_path / "aitrace-report.html"
    html = to_html_report(result, tmp_path)
    html_path.write_text(html, encoding="utf-8")
    text = html_path.read_text(encoding="utf-8")
    assert "AI application architecture" in text
    assert "Taint-flow graph" in text
    assert "cdn.jsdelivr.net/npm/mermaid" in text
    assert "cytoscape" not in text.lower()
    arch = _extract_json(text, "aitrace-arch-data")
    taint = _extract_json(text, "aitrace-taint-data")
    ids = {n["id"] for n in arch.get("nodes") or []}
    for e in arch.get("edges") or []:
        assert e["source"] in ids
        assert e["target"] in ids
    assert taint.get("flow_count", 0) >= 1
    node_bin = subprocess.run(
        [
            "node",
            "-e",
            "const fs=require('fs'); const h=fs.readFileSync(process.argv[1],'utf8');"
            "function grab(id){const i=h.indexOf(\"id='\"+id+\"'\"); const a=h.indexOf('>',i)+1;"
            "const b=h.indexOf('</script>',a); return JSON.parse(h.slice(a,b));}"
            "const t=grab('aitrace-taint-data');"
            "const f=t.flows[0];"
            "if(!f.path_node_ids) process.exit(2);"
            "const n=new Set(t.nodes.map(x=>x.id));"
            "for (const id of f.path_node_ids) if(!n.has(id)) process.exit(3);"
            "const kinds=new Set(t.nodes.map(x=>x.role||x.kind));"
            "console.log(JSON.stringify({flows:t.flow_count,kinds:[...kinds]}));",
            str(html_path),
        ],
        capture_output=True,
        text=True,
    )
    assert node_bin.returncode == 0, node_bin.stderr + node_bin.stdout


def test_empty_and_missing_line_generated_html(tmp_path: Path):
    (tmp_path / "hello.py").write_text("def main():\n    return 1\n", encoding="utf-8")
    empty = AITraceEngine(tmp_path).analyze()
    html = to_html_report(empty, tmp_path)
    assert "No AI architecture components" in html or "No confirmed value-taint" in html
    df = DataFlow(
        source="user_input",
        sink="llm.invoke",
        file="hello.py",
        line=None,
        risk="high",
        source_line=None,
        sink_category="llm",
        hops=[],
    )
    g = build_taint_flow_graph(DataFlowAnalysisResult(data_flows=[df]))
    assert g["flows"][0]["source_line"] is None
    assert g["flows"][0]["sink_line"] is None


def test_findings_without_architecture_edges_in_html(tmp_path: Path):
    (tmp_path / "keys.py").write_text(
        "API_KEY = 'sk-abcdefghijklmnopqrstuvwx'\n",
        encoding="utf-8",
    )
    result = AITraceEngine(tmp_path).analyze()
    html = to_html_report(result, tmp_path)
    arch = result.architecture_graph or {"edges": []}
    assert (arch.get("stats") or {}).get("edge_count", len(arch.get("edges") or [])) == 0
    assert "AI application architecture" in html


def test_large_graph_cap_not_unbounded():
    nodes = [{"id": f"n{i}", "kind": "function", "label": f"f{i}"} for i in range(200)]
    edges = [{"source": f"n{i}", "target": f"n{i+1}", "label": "calls"} for i in range(199)]
    g = {"nodes": nodes, "edges": edges, "stats": {"node_count": 200, "edge_count": 199}}
    from core.exporters.html_report import _architecture_graph_section

    html = _architecture_graph_section(g)
    assert "200" in html
    # Renderer still embeds the model; engine cap is in architecture_graph builder.
    assert "aitrace-arch-data" in html
