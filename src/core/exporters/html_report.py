"""HTML report exporter — single self-contained aitrace-report.html with full scan detail."""

from __future__ import annotations

import html as _html
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

from .finding_contract import filter_security_findings
from .overview_diagram import (
    build_overview,
    taint_flow_svg,
    taint_narrative_html,
    taint_steps,
)

if TYPE_CHECKING:
    from core.engine import AnalysisResult
    from core.features.exploit_synthesizer import ExploitPayload
    from core.features.finding_verifier import VerificationResult

_SEV_COLOR: Dict[str, str] = {
    "CRITICAL": "#b91c1c",
    "HIGH": "#c2410c",
    "MEDIUM": "#a16207",
    "LOW": "#15803d",
    "INFO": "#475569",
}
_SEV_ORDER: Dict[str, int] = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}
_SOURCE_BADGE: Dict[str, str] = {
    "llm_verified": "verified",
    "taint_confirmed": "path confirmed",
    "pattern": "AI risk",
    "semantic": "AI risk",
    "surface": "inventory",
    "deep": "config",
    "policy": "policy",
}

# Plain-language titles for conference / executive audiences
_PLAIN_PAT_TITLES: Dict[str, str] = {
    "PAT-001": "User input reaches the AI without being cleaned",
    "PAT-002": "AI agent can run arbitrary code on the server",
    "PAT-003": "AI-written SQL runs without safety checks",
    "PAT-004": "AI output is executed as code",
    "PAT-005": "One agent’s output is trusted as system instructions",
    "PAT-006": "Conversation memory can grow without limit",
    "PAT-007": "High-impact action runs without human approval",
    "PAT-008": "External data is inserted into prompts unchecked",
    "PAT-009": "Model files load in an unsafe way",
    "PAT-010": "Secrets or API keys are hardcoded in source",
    "PAT-011": "AI answers are returned to users without checking",
    "PAT-012": "Sensitive data, untrusted input, and exfiltration together",
    "PAT-013": "Agents trust each other across unsafe boundaries",
    "PAT-014": "Agent memory is stored and reloaded without integrity checks",
    "PAT-015": "AI-generated code runs without a sandbox",
    "PAT-016": "Tool results are fed back to the agent unchecked",
    "PAT-017": "Streaming AI responses skip output checks",
    "PAT-018": "External data sources can poison AI prompts",
    "PAT-019": "AI model loaded without integrity verification",
    "PAT-020": "Anyone can upload files that may poison the knowledge base",
    "PAT-021": "MCP tool responses can hijack the agent",
    "PAT-022": "Known-vulnerable AI package in use",
    "PAT-023": "Agent output is promoted to trusted system context",
    "PAT-024": "Irreversible action runs without a human in the loop",
    "PAT-025": "User input is executed as a shell command",
    "PAT-026": "User messages are written into the AI knowledge base",
    "PAT-027": "AI agent has a high-impact tool with no approval gate",
    "PAT-028": "Secrets sit in documents the AI can retrieve",
    "FLOW-RCE": "Untrusted input reaches command execution",
    "FLOW-SQL": "Untrusted input is interpolated into a SQL string",
    "FLOW-LLM": "Untrusted input reaches an LLM prompt",
    "FLOW-HTTP": "Untrusted input selects an outbound HTTP destination",
    "FLOW-EMAIL": "Untrusted input reaches an email send",
    "FLOW-RAG": "Untrusted input is written into the vector store",
}

_PLAIN_TITLE_PREFIXES: Tuple[Tuple[str, str], ...] = (
    ("MCP poisoned tool description", "MCP tool description looks manipulated"),
    ("MCP server response injection", "MCP server can inject instructions into the agent"),
    ("MCP tool shadowing", "Two MCP tools share the same name — wrong one may run"),
    ("Hardcoded credentials in MCP server config", "Secrets stored in MCP server configuration"),
    ("Poisoned tool definition file detected", "Tool definition file contains suspicious instructions"),
    ("LLM inference detected", "Direct calls to an AI model were found"),
)


def _e(v: object) -> str:
    return _html.escape(str(v))


def _how_to_read(body_html: str) -> str:
    """Collapsed, accessible explanation — keep the page scannable."""
    return (
        "<details class='howto'>"
        "<summary>How to read this</summary>"
        f"<div class='howto-body'>{body_html}</div></details>"
    )


def _nav() -> str:
    """In-page section navigation for long assessment reports."""
    return (
        "<nav class='toc' aria-label='Report sections'>"
        "<a href='#summary'>Summary</a>"
        "<a href='#ai-overview'>Overview</a>"
        "<a href='#findings'>Findings</a>"
        "<a href='#taint-flow-graph'>Taint paths</a>"
        "<a href='#downloads'>Downloads</a>"
        "</nav>"
    )


_CSS = """
:root{--bg:#f4f6f8;--card:#ffffff;--border:#d7dee8;--text:#132033;--muted:#5b6b7c;--accent:#1d4ed8;--soft:#eef2f7}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:var(--bg);color:var(--text);padding:1.5rem 1.75rem 3rem;max-width:1180px;margin:auto;line-height:1.45}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
h2{font-size:.78rem;font-weight:700;color:#334155;text-transform:uppercase;letter-spacing:.07em;margin-bottom:.85rem}
h3{font-size:.72rem;font-weight:700;color:#64748b;text-transform:uppercase;letter-spacing:.06em;margin:1.25rem 0 .6rem}
.section{margin-bottom:2rem}
.hdr{margin-bottom:1.25rem;padding-bottom:1rem;border-bottom:1px solid var(--border)}
.hdr-title{font-size:1.55rem;font-weight:700;letter-spacing:-.02em}
.hdr-sub{font-size:.875rem;color:var(--muted);margin-top:.3rem}
.toc{display:flex;flex-wrap:wrap;gap:.45rem .75rem;margin:0 0 1.4rem;padding:.7rem .85rem;background:var(--card);border:1px solid var(--border);border-radius:.6rem}
.toc a{font-size:.78rem;font-weight:600;color:#1e3a8a}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:.85rem;margin-bottom:1.5rem}
.card{background:var(--card);border:1px solid var(--border);border-radius:.7rem;padding:1rem 1.05rem;box-shadow:0 1px 2px #1320330d}
.card-val{font-size:1.7rem;font-weight:700;line-height:1;color:#0f172a}
.card-lbl{font-size:.75rem;color:var(--muted);margin-top:.35rem}
.sev-row{display:flex;flex-wrap:wrap;gap:.35rem;margin-top:.5rem}
.sev-chip{font-size:.65rem;font-weight:700;padding:.18rem .45rem;border-radius:.25rem;text-transform:uppercase}
.comp-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(170px,1fr));gap:.55rem}
.comp-card{background:var(--card);border:1px solid var(--border);border-radius:.5rem;padding:.65rem .8rem;min-width:0;overflow:hidden}
.comp-name{font-weight:600;font-size:.86rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.comp-ver{color:var(--muted);font-size:.74rem}
.comp-type{font-size:.65rem;color:#475569;text-transform:uppercase;letter-spacing:.04em;margin-bottom:.15rem}
.mcp-list{display:flex;flex-direction:column;gap:.55rem}
.mcp-row{background:var(--card);border:1px solid var(--border);border-radius:.5rem;padding:.75rem 1rem}
.mcp-head{display:flex;align-items:center;gap:.75rem;flex-wrap:wrap}
.mcp-name{font-weight:600;font-size:.9rem}
.mcp-meta{font-size:.75rem;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--muted);margin-left:auto;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:320px}
.inj-badge{font-size:.65rem;font-weight:700;padding:.2rem .5rem;border-radius:.25rem;background:#fee2e2;color:#b91c1c;flex-shrink:0}
.mcp-findings{margin-top:.5rem;padding-left:1rem;font-size:.78rem;color:var(--muted);line-height:1.4}
.src-badge{font-size:.62rem;font-weight:700;padding:.15rem .4rem;border-radius:.25rem;background:var(--soft);color:#334155;text-transform:lowercase;flex-shrink:0;margin-top:.15rem;white-space:nowrap}
details.finding{background:var(--card);border:1px solid var(--border);border-left:4px solid var(--border);border-radius:.65rem;overflow:hidden;margin-bottom:.55rem;box-shadow:0 1px 2px #1320330a}
details.finding summary{list-style:none;padding:.85rem 1rem;cursor:pointer;display:flex;align-items:flex-start;gap:.55rem;user-select:none}
details.finding summary::-webkit-details-marker{display:none}
details.finding[open]>summary{border-bottom:1px solid var(--border);background:#f8fafc}
.f-chevron{flex-shrink:0;margin-top:.2rem;color:var(--muted);transition:transform .15s}
details.finding[open] .f-chevron{transform:rotate(90deg)}
.f-body{padding:.9rem 1rem;display:flex;flex-direction:column;gap:.45rem}
.sev-badge{font-size:.65rem;font-weight:700;padding:.2rem .55rem;border-radius:.25rem;text-transform:uppercase;flex-shrink:0;margin-top:.1rem;white-space:nowrap}
.finding-title{font-weight:650;font-size:.95rem;flex:1}
.finding-desc{color:#3f4f61;font-size:.85rem;line-height:1.45}
.finding-loc{font-size:.75rem;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--accent)}
.finding-count{font-size:.7rem;font-weight:700;padding:.15rem .45rem;border-radius:.25rem;background:var(--soft);color:#334155;flex-shrink:0;margin-top:.15rem}
.finding-id{font-size:.7rem;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:#475569}
.ev-meta{display:flex;flex-wrap:wrap;gap:.4rem;margin:.15rem 0}
.sub-finding{border-top:1px solid var(--border);padding-top:.65rem;margin-top:.25rem}
.sub-finding:first-child{border-top:none;padding-top:0;margin-top:0}
.table-wrap{overflow:auto;border:1px solid var(--border);border-radius:.65rem;background:var(--card)}
table{width:100%;border-collapse:collapse;font-size:.8rem}
th,td{padding:.58rem .7rem;border-bottom:1px solid var(--border);text-align:left;vertical-align:top}
th{color:#475569;font-size:.68rem;text-transform:uppercase;letter-spacing:.04em;background:#f1f5f9}
tr:last-child td{border-bottom:none}
.path-card{background:var(--card);border:1px solid var(--border);border-radius:.5rem;padding:.75rem 1rem;margin-bottom:.5rem;font-size:.85rem}
.path-chain{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:#1e3a8a;margin-top:.35rem;line-height:1.45;word-break:break-word}
.hop-list{display:flex;flex-wrap:wrap;align-items:baseline;gap:.2rem .05rem}
.hop{padding:.08rem .28rem;border-radius:.25rem}
.hop-src{background:#dbeafe;color:#1e3a8a}
.hop-mid{background:#f1f5f9;color:#334155}
.hop-sink{background:#fee2e2;color:#991b1b}
.hop-arrow{color:#94a3b8;font-weight:600}
.mmd-wrap{background:var(--card);border:1px solid var(--border);border-radius:.65rem;padding:1.15rem;overflow:auto}
.dl-row{display:flex;flex-wrap:wrap;gap:.65rem}
.dl-btn{display:inline-block;padding:.45rem .9rem;background:var(--card);border:1px solid var(--accent);border-radius:.45rem;color:var(--accent);font-size:.84rem;text-decoration:none}
.dl-btn:hover{background:var(--accent);color:#fff;text-decoration:none}
.empty{color:var(--muted);font-size:.875rem;padding:.85rem 0}
.eval-meta{width:100%;margin:.75rem 0 1rem;font-size:.8rem}
.eval-meta th{width:8rem}
button[data-eval-filter],button[data-show-taint-flow]{margin-right:.35rem;margin-bottom:.35rem;padding:.25rem .55rem;background:var(--card);border:1px solid var(--border);color:var(--text);border-radius:.35rem;cursor:pointer;font-size:.75rem}
button[data-show-taint-flow]{border-color:var(--accent);color:var(--accent)}
.policy-pass{color:#15803d}.policy-fail{color:#b91c1c}
details.exploit-card{background:var(--card);border:1px solid #fecaca;border-left:3px solid #b91c1c;border-radius:.65rem;overflow:hidden;margin-bottom:.5rem}
details.exploit-card summary{list-style:none;padding:.875rem 1rem;cursor:pointer;display:flex;align-items:flex-start;gap:.6rem;user-select:none}
details.exploit-card summary::-webkit-details-marker{display:none}
details.exploit-card[open]>summary{border-bottom:1px solid var(--border)}
details.exploit-card[open] .f-chevron{transform:rotate(90deg)}
.exploit-body{padding:1rem;display:flex;flex-direction:column;gap:.75rem}
.exploit-meta{display:flex;flex-wrap:wrap;gap:.5rem}
.exploit-meta-pill{font-size:.72rem;padding:.2rem .6rem;border-radius:.25rem;background:var(--soft);color:var(--muted)}
.exploit-meta-pill strong{color:var(--text);font-weight:600}
.exploit-desc{font-size:.85rem;color:var(--muted);line-height:1.5}
.payload-block{background:#0f172a;border:1px solid #1e293b;border-radius:.5rem;overflow:auto;max-height:220px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.76rem;line-height:1.6}
.pl{display:flex}
.pl:hover{background:#ffffff0d}
.ln{min-width:2.6rem;text-align:right;padding:0 .75rem;color:#64748b;user-select:none;flex-shrink:0;border-right:1px solid #1e293b}
.lc{color:#e2e8f0;white-space:pre;padding:0 .75rem}
.verdict-box{border-radius:.5rem;padding:.6rem .75rem;background:#f8fafc}
.verify-ev{font-size:.8rem;padding:.15rem 0;display:flex;gap:.4rem;align-items:flex-start}
details.exploit-gate{margin-bottom:2rem}
details.exploit-gate>summary{list-style:none;cursor:pointer;display:flex;align-items:center;gap:.75rem;padding:1rem 1.15rem;background:#fef2f2;border:1px solid #fecaca;border-radius:.65rem;user-select:none}
details.exploit-gate>summary::-webkit-details-marker{display:none}
details.exploit-gate[open]>summary{border-radius:.65rem .65rem 0 0}
.gate-lock{font-size:1.1rem;flex-shrink:0}
.gate-title{font-size:.85rem;font-weight:700;color:#991b1b;flex:1}
.gate-subtitle{font-size:.75rem;color:#b91c1c}
.gate-chevron{flex-shrink:0;color:#b91c1c;transition:transform .15s}
details.exploit-gate[open] .gate-chevron{transform:rotate(90deg)}
.gate-body{background:#fff;border:1px solid #fecaca;border-top:none;border-radius:0 0 .65rem .65rem;padding:1.15rem}
.gate-warning{font-size:.8rem;color:#9a3412;background:#fff7ed;border:1px solid #fed7aa;border-radius:.5rem;padding:.6rem .875rem;margin-bottom:.75rem}
.graph-shell{background:var(--card);border:1px solid var(--border);border-radius:.65rem;overflow:auto;max-height:680px;margin-bottom:.75rem}
.graph-toolbar{display:flex;flex-wrap:wrap;gap:.5rem;align-items:center;padding:.65rem .75rem;border-bottom:1px solid var(--border);background:#f8fafc;position:sticky;top:0;z-index:1}
.graph-toolbar input,.graph-toolbar select{background:#fff;border:1px solid var(--border);color:var(--text);border-radius:.4rem;padding:.32rem .5rem;font-size:.8rem}
.graph-toolbar button{background:#fff;border:1px solid var(--accent);color:var(--accent);border-radius:.4rem;padding:.32rem .6rem;font-size:.75rem;cursor:pointer}
.graph-canvas{display:block;width:auto;height:auto;min-width:100%;background:#f8fafc;touch-action:none}
.graph-canvas[hidden],.graph-detail[hidden]{display:none!important}
.graph-detail{padding:.8rem 1rem;font-size:.8rem;color:#334155;min-height:3rem;border-top:1px solid var(--border);white-space:pre-wrap;background:#fff}
.graph-fallback{font-size:.8rem;margin-top:.5rem}
.graph-fallback li{margin:.25rem 0;color:var(--muted)}
.graph-legend{display:flex;flex-wrap:wrap;gap:.5rem;margin:.45rem 0 .7rem;font-size:.7rem;color:var(--muted)}
.graph-legend span{display:inline-flex;align-items:center;gap:.3rem}
.graph-swatch{width:.65rem;height:.65rem;border-radius:50%;display:inline-block}
details.howto{margin:.35rem 0 .85rem;border:1px solid var(--border);border-radius:.5rem;background:#fff}
details.howto>summary{cursor:pointer;list-style:none;padding:.45rem .7rem;font-size:.78rem;font-weight:650;color:#1e3a8a}
details.howto>summary::-webkit-details-marker{display:none}
.howto-body{padding:.15rem .75rem .7rem;font-size:.8rem;color:#3f4f61;line-height:1.5}
.howto-body ul{margin:.35rem 0 0 1.1rem}
.view-tabs{display:flex;gap:.25rem;margin:0 0 .85rem;border-bottom:1px solid var(--border)}
.view-tabs button{background:transparent;border:none;border-bottom:2px solid transparent;color:#475569;padding:.45rem .8rem;font-size:.8rem;font-weight:650;cursor:pointer}
.view-tabs button[aria-selected='true']{color:var(--accent);border-bottom-color:var(--accent)}
.wf-grid{display:flex;flex-direction:column;gap:.85rem}
.wf-card{background:var(--card);border:1px solid var(--border);border-radius:.65rem;padding:.75rem .9rem;overflow:auto}
.wf-title{font-size:.8rem;font-weight:700;margin-bottom:.45rem;color:#0f172a}
.wf-meta{font-size:.72rem;color:var(--muted);margin-bottom:.45rem}
.wf-legend{display:flex;flex-wrap:wrap;gap:.55rem .9rem;margin:.15rem 0 .65rem;font-size:.72rem;color:#334155}
.wf-legend span{display:inline-flex;align-items:center;gap:.35rem}
.wf-line{width:1.35rem;height:0;border-top:2.2px solid #6366f1;display:inline-block}
.wf-line.dashed{border-top-style:dashed;border-top-color:#94a3b8}
.wf-swatch.sink{width:.7rem;height:.7rem;border-radius:.15rem;background:#ffe4e6;border:1.5px solid #e11d48;display:inline-block}
.wf-svg{display:block;max-width:100%;height:auto}
.wf-detail{font-size:.78rem;color:#334155;white-space:pre-wrap;margin-top:.55rem;line-height:1.45}
.disc-row{display:flex;flex-wrap:wrap;gap:.45rem}
.disc-chip{background:#fff;border:1px solid var(--border);border-radius:.45rem;padding:.4rem .6rem;font-size:.75rem;max-width:220px}
.disc-chip strong{display:block;font-size:.72rem;color:#334155}
.disc-chip span{color:var(--muted);font-size:.68rem;font-family:ui-monospace,Menlo,monospace}
.inv-toolbar{display:flex;flex-wrap:wrap;gap:.5rem;margin:0 0 .65rem}
.inv-toolbar input,.inv-toolbar select{background:#fff;border:1px solid var(--border);border-radius:.4rem;padding:.32rem .5rem;font-size:.8rem}
.taint-flow-panel{display:none}
.taint-flow-panel.is-active{display:block;padding:.85rem 1rem 1.05rem}
.taint-story{font-size:.9rem;color:#0f172a;line-height:1.5;margin:0 0 .75rem}
.taint-story code{background:#eff6ff;color:#1e3a8a;padding:.05rem .32rem;border-radius:.25rem;font-size:.84em}
.taint-caption{font-size:.72rem;color:#64748b;margin:.4rem 0 .65rem}
.taint-path-table{margin:.1rem 0 .55rem}
.taint-path-table table{width:100%;border-collapse:collapse;font-size:.8rem}
.taint-path-table th,.taint-path-table td{text-align:left;padding:.4rem .55rem;border-bottom:1px solid var(--border);vertical-align:top}
.taint-path-table th{color:#64748b;font-weight:650;font-size:.7rem;letter-spacing:.03em;text-transform:uppercase}
.taint-fn{font-family:ui-monospace,Menlo,monospace;font-size:.72rem;color:#64748b;margin-top:.12rem}
.taint-pills{display:flex;flex-wrap:wrap;gap:.35rem;margin:.2rem 0 .35rem}
.taint-pill{font-size:.7rem;background:#f8fafc;border:1px solid #e2e8f0;padding:.12rem .45rem;border-radius:.3rem;color:#475569}
.taint-meta{font-size:.78rem;color:#334155;margin-top:.5rem;white-space:pre-wrap}
.wf-detail{font-size:.78rem;color:#334155;margin-top:.5rem;min-height:1.2rem}
"""

_CHEVRON = (
    "<svg class='f-chevron' width='14' height='14' viewBox='0 0 24 24' fill='none' "
    "stroke='currentColor' stroke-width='2.5'><polyline points='9 18 15 12 9 6'/></svg>"
)


def _head(repo_name: str) -> str:
    return (
        "<!DOCTYPE html><html lang='en'><head>"
        "<meta charset='UTF-8'>"
        f"<title>AITrace — {_e(repo_name)}</title>"
        f"<style>{_CSS}</style>"
        "</head>"
    )


def _header(repo_name: str, timestamp: str, repo_type: str) -> str:
    """Render page header — title and scan metadata only."""
    return (
        f"<div class='hdr'>"
        f"<div class='hdr-title'>{_e(repo_name)}</div>"
        f"<div class='hdr-sub'>{_e(timestamp)} · {_e(repo_type)} repo</div>"
        f"</div>"
    )


def _sev_chip(label: str, count: int) -> str:
    if count == 0:
        return ""
    color = _SEV_COLOR.get(label.upper(), "#94a3b8")
    return (
        f"<span class='sev-chip' style='background:{color}22;color:{color}'>"
        f"{_e(count)} {_e(label.lower())}</span>"
    )


def _summary_cards(
    n_comp: int,
    n_mcp: int,
    n_findings: int,
    sev_counts: Dict[str, int],
    n_dataflows: int,
    n_exposures: int,
) -> str:
    """Metric cards for findings, components, dataflows, and exposures."""
    finding_chips = "".join(
        _sev_chip(s, sev_counts.get(s, 0))
        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    )
    lib_count = max(n_comp - n_mcp, 0)
    return (
        f"<div class='cards' id='summary'>"
        f"<div class='card'><div class='card-val'>{n_findings}</div>"
        f"<div class='card-lbl'>Security findings</div>"
        f"<div class='sev-row'>{finding_chips}</div></div>"
        f"<div class='card'><div class='card-val'>{n_comp}</div>"
        f"<div class='card-lbl'>AI components</div>"
        f"<div class='sev-row'>"
        f"<span class='sev-chip' style='background:#e0e7ff;color:#3730a3'>{lib_count} libraries</span>"
        f"<span class='sev-chip' style='background:#e0f2fe;color:#075985'>{n_mcp} MCP</span>"
        f"</div></div>"
        f"<div class='card'><div class='card-val'>{n_dataflows}</div>"
        f"<div class='card-lbl'>Data flows</div></div>"
        f"<div class='card'><div class='card-val'>{n_exposures}</div>"
        f"<div class='card-lbl'>Sensitive exposures</div></div>"
        f"</div>"
    )


def _inventory_table(rows: List[Dict[str, str]], types: List[str]) -> str:
    """Searchable, filterable component inventory (packages, MCP, observed sites)."""
    if not rows:
        return "<div class='empty' id='ai-components'>No AI packages or observed components.</div>"
    options = "".join(f"<option value='{_e(t)}'>{_e(t)}</option>" for t in types)
    body = []
    for r in rows:
        body.append(
            "<tr data-inv-row data-type='"
            + _e(r.get("type"))
            + "' data-name='"
            + _e((r.get("name") or "").lower())
            + "'>"
            f"<td>{_e(r.get('name'))}</td>"
            f"<td>{_e(r.get('type'))}</td>"
            f"<td>{_e(r.get('provider') or '—')}</td>"
            f"<td>{_e(r.get('model') or '—')}</td>"
            f"<td class='finding-loc'>{_e(r.get('source') or '—')}</td>"
            f"<td>{_e(r.get('evidence') or '—')}</td>"
            "</tr>"
        )
    return (
        "<div id='ai-components'>"
        "<div class='inv-toolbar'>"
        "<input data-inv-search placeholder='Search component' aria-label='Search components'>"
        "<select data-inv-filter aria-label='Filter component type'>"
        "<option value=''>All types</option>"
        f"{options}</select></div>"
        "<div class='table-wrap'><table><thead><tr>"
        "<th>Name</th><th>Type</th><th>Provider / framework</th>"
        "<th>Model</th><th>Source</th><th>Evidence</th>"
        "</tr></thead><tbody>"
        + "".join(body)
        + "</tbody></table></div></div>"
    )


def _omitted_reason(node: Dict[str, Any]) -> str:
    """Short reason a node is off the compact map."""
    path = str(node.get("file") or node.get("source_file") or "").replace("\\", "/")
    if path.startswith("scripts/") or "/scripts/" in path:
        return "seed/script — not part of request handling"
    if str(node.get("kind") or "") == "api_endpoint":
        return "no calls into the AI app (health, sessions, static)"
    return "omitted from this view"


def _chip_row(nodes: List[Dict[str, Any]], *, reason: bool = False) -> str:
    """Compact identity chips for omitted / disconnected lists."""
    chips = []
    for n in nodes:
        loc = n.get("file") or ""
        if n.get("line"):
            loc = f"{loc}:{n.get('line')}"
        extra = _omitted_reason(n) if reason else (loc or n.get("evidence") or "")
        chips.append(
            "<div class='disc-chip'>"
            f"<strong>{_e(n.get('kind'))}: {_e(n.get('label'))}</strong>"
            f"<span>{_e(extra)}</span></div>"
        )
    return f"<div class='disc-row'>{''.join(chips)}</div>"


def _disconnected_html(nodes: List[Dict[str, Any]]) -> str:
    """Isolated observed components — no invented edges."""
    if not nodes:
        return ""
    return (
        "<div class='wf-card'>"
        "<div class='wf-title'>Disconnected components</div>"
        "<div class='wf-meta'>Observed in source with no recorded call relationship.</div>"
        + _chip_row(nodes)
        + "</div>"
    )


def _omitted_html(nodes: List[Dict[str, Any]]) -> str:
    """Unused routes and seed scripts tucked off the compact map."""
    if not nodes:
        return ""
    return (
        "<div class='wf-card'>"
        "<div class='wf-title'>Not shown on this map</div>"
        "<div class='wf-meta'>Health checks, session CRUD, and seed scripts "
        "are listed here so the diagram only shows routes that call into the app.</div>"
        + _chip_row(nodes, reason=True)
        + "</div>"
    )


def _overview_section(
    graph: Optional[Dict[str, Any]],
    components: list,
    mcp_servers: list,
) -> str:
    """Combined architecture diagrams and searchable inventory."""
    overview = build_overview(graph, components, mcp_servers)
    workflows = list(overview.get("workflows") or [])
    cards = []
    for wf in workflows:
        hidden = list(wf.get("hidden_node_ids") or [])
        drill = ""
        if hidden:
            by_id = {str(n.get("id")): n for n in wf.get("nodes") or []}
            items = []
            for hid in hidden:
                n = by_id.get(hid) or {}
                loc = n.get("file") or ""
                if n.get("line"):
                    loc = f"{loc}:{n.get('line')}"
                items.append(
                    f"<li>{_e(n.get('kind'))}: {_e(n.get('label'))}"
                    f"{(' @ ' + _e(loc)) if loc else ''} — {_e(n.get('evidence') or '')}</li>"
                )
            drill = (
                "<details class='howto'><summary>"
                f"{len(hidden)} additional observed components</summary>"
                f"<ul class='graph-fallback'>{''.join(items)}</ul></details>"
            )
        cards.append(
            "<div class='wf-card'>"
            f"<div class='wf-title'>{_e(wf.get('title') or 'How requests reach AI and data sinks')}</div>"
            f"<div class='wf-meta'>Each box is a layer of the running app. "
            f"Arrows only cross between boxes (calls inside a box are hidden). "
            f"{int(wf.get('node_count') or 0)} components · "
            f"{int(wf.get('edge_count') or 0)} arrows</div>"
            "<div class='wf-legend'>"
            "<span><i class='wf-line'></i> Solid — this function calls that one (verified in source)</span>"
            "<span><i class='wf-line dashed'></i> Dashed — constructs or registers, not a runtime call</span>"
            "<span><i class='wf-swatch sink'></i> Red box — trust-boundary sinks "
            "(LLM, SQL, email, MCP). Presence here is not a confirmed taint path.</span>"
            "</div>"
            + str(wf.get("svg") or "")
            + "<div class='wf-detail' data-wf-detail>Select a component for file and evidence.</div>"
            + drill
            + "</div>"
        )
    arch_body = (
        "".join(cards)
        + _omitted_html(list(overview.get("omitted") or []))
        + _disconnected_html(list(overview.get("disconnected") or []))
        if cards or overview.get("disconnected") or overview.get("omitted")
        else (
            "<div class='empty'>No AI architecture components were identified from "
            "source evidence. Package inventory is listed under AI Components.</div>"
        )
    )
    kinds = sorted({
        str(n.get("kind") or "")
        for n in (graph or {}).get("nodes") or []
        if n.get("kind")
    })
    howto = _how_to_read(
        "<ul>"
        "<li>This map answers: which HTTP routes actually reach AI tools, models, "
        "databases, or email? Health and session routes stay off the picture.</li>"
        "<li>Solid arrows are verified calls. Dashed arrows mean constructs or "
        "registers. Arrows inside the same coloured box are omitted to reduce clutter.</li>"
        "<li>The red box is the trust boundary — LLM APIs, SQL, SMTP, MCP servers. "
        "A node there is a sink, not proof that user input reaches it. Confirmed "
        "value-to-sink paths are under Taint paths.</li>"
        "</ul>"
    )
    return (
        "<div class='section' id='ai-overview'>"
        "<h2>AI Application Overview</h2>"
        + howto
        + _legend_html(kinds)
        + "<div class='view-tabs' role='tablist'>"
        "<button type='button' role='tab' aria-selected='true' data-overview-tab='arch'>"
        "Architecture</button>"
        "<button type='button' role='tab' aria-selected='false' data-overview-tab='inv'>"
        "AI Components</button>"
        "</div>"
        "<div id='architecture-graph' data-overview-panel='arch'>"
        f"<div class='wf-grid'>{arch_body}</div></div>"
        "<div data-overview-panel='inv' hidden>"
        + _inventory_table(
            list(overview.get("inventory") or []),
            list(overview.get("inventory_types") or []),
        )
        + "</div>"
        + _json_script("aitrace-arch-data", graph or {"nodes": [], "edges": []})
        + _json_script("aitrace-overview-data", {
            "stats": overview.get("stats"),
            "original_node_ids": overview.get("original_node_ids"),
        })
        + "</div>"
    )


def _source_badge(category: Any) -> str:
    """Human-readable source badge for a finding category."""
    key = getattr(category, "value", str(category))
    label = _SOURCE_BADGE.get(key, key)
    return f"<span class='src-badge'>{_e(label)}</span>"


# Titles that should collapse variants like "…: filesystem" into one expandable group
_GROUP_TITLE_PREFIXES: Tuple[str, ...] = (
    "MCP poisoned tool description",
    "MCP server response injection",
    "MCP tool shadowing",
    "Hardcoded credentials in MCP server config",
    "Poisoned tool definition file detected",
)


def _plain_title(finding: Any) -> str:
    """Executive-friendly title for a finding."""
    fid = str(getattr(finding, "id", "") or "")
    if fid in _PLAIN_PAT_TITLES:
        return _PLAIN_PAT_TITLES[fid]
    title = (getattr(finding, "title", "") or "").strip()
    for prefix, plain in _PLAIN_TITLE_PREFIXES:
        if title == prefix or title.startswith(prefix + ":"):
            suffix = title[len(prefix) + 1 :].strip() if title.startswith(prefix + ":") else ""
            return f"{plain}: {suffix}" if suffix else plain
    return title


def _group_key(finding: Any) -> str:
    """
    Key used to collapse related findings into one dropdown.

    PAT-* findings group by pattern ID; MCP titles use prefix rules.
    """
    fid = str(getattr(finding, "id", "") or "")
    if fid.startswith("PAT-"):
        return fid
    title = (getattr(finding, "title", "") or "").strip()
    for prefix in _GROUP_TITLE_PREFIXES:
        if title == prefix or title.startswith(prefix + ":"):
            return prefix
    return title


def _display_group_title(group_key: str, group: list) -> str:
    """Plain-language summary title for a finding group."""
    return _plain_title(group[0])


def _instance_label(finding: Any, group_key: str) -> str:
    """Short label for one instance inside an expanded group (usually a file path)."""
    title = (getattr(finding, "title", "") or "").strip()
    loc = _finding_loc_str(finding)
    if group_key.startswith("PAT-"):
        return loc or "In scanned source"
    if title.startswith(group_key + ":"):
        name = title[len(group_key) + 1 :].strip()
        return f"{name} — {loc}" if loc and name else (name or loc or title)
    return loc or title or "Instance"


def _group_findings(findings: list) -> List[Tuple[str, list, str]]:
    """Group findings by normalized key; return (group_key, group, best_sev)."""
    groups: Dict[str, list] = defaultdict(list)
    for f in findings:
        groups[_group_key(f)].append(f)

    result = []
    for key, group in groups.items():
        best_order = min(_SEV_ORDER.get(f.severity.value.upper(), 99) for f in group)
        best_sev = next(
            f.severity.value.upper()
            for f in group
            if _SEV_ORDER.get(f.severity.value.upper(), 99) == best_order
        )
        result.append((key, group, best_sev, best_order))

    result.sort(key=lambda x: x[3])
    return [(k, g, s) for k, g, s, _ in result]


def _finding_loc_str(f: Any) -> str:
    """Extract a location string from a finding's evidence."""
    if f.evidence:
        ev = f.evidence[0]
        if ev.file:
            return ev.file + (f":{ev.line}" if ev.line else "")
    return ""


def _taint_paths_by_pattern(crossfile_taint: Any) -> Dict[str, List[str]]:
    """Map PAT-* id → short plain-language attack-path summaries."""
    out: Dict[str, List[str]] = defaultdict(list)
    if crossfile_taint is None:
        return out
    for tp in getattr(crossfile_taint, "taint_paths", []) or []:
        if not getattr(tp, "confirmed", False):
            continue
        hops = [
            h.split("::")[-1] if "::" in h else h
            for h in getattr(tp, "hops", [])
            if "(sink not reached)" not in h
        ]
        if not hops:
            continue
        chain = " → ".join(hops)
        sink = getattr(tp, "sink_type", "AI")
        label = f"Attack path to {sink}: {chain}"
        for pid in getattr(tp, "confirms_pattern_ids", None) or []:
            if label not in out[pid]:
                out[pid].append(label)
    return out


def _why_it_matters(finding: Any) -> str:
    """One-line business impact for executive / CFP audiences."""
    fid = str(getattr(finding, "id", "") or "")
    sev = finding.severity.value.upper()
    if fid == "FLOW-LLM":
        return "User-controlled text reaches the model prompt and must be treated as untrusted."
    if fid == "PAT-002":
        return "An attacker could run commands on your servers through the AI agent."
    if fid in ("PAT-001", "PAT-008", "PAT-018"):
        return "Attackers may steer the AI with crafted input or poisoned data."
    if fid in ("PAT-003", "PAT-004", "PAT-025", "FLOW-RCE", "FLOW-SQL"):
        return "AI output could change or damage databases and systems."
    if fid in ("PAT-010",) or "credential" in (getattr(finding, "title", "") or "").lower():
        return "Secrets in config can be stolen and used to access other systems."
    if fid in ("PAT-012", "PAT-023", "PAT-005"):
        return "Sensitive data can leave your environment via the AI stack."
    if fid in ("PAT-020", "PAT-026", "FLOW-RAG"):
        return "Uploaded content can poison what the AI tells users."
    if fid in ("PAT-027", "FLOW-HTTP", "FLOW-EMAIL"):
        return "The agent can email, fetch URLs, or act without a human in the loop."
    if fid == "PAT-028":
        return "Retrieved documents may leak passwords or keys to users or the model."
    if fid.startswith("PAT-") and sev in ("CRITICAL", "HIGH"):
        return "This creates a realistic path for abuse of your AI application."
    if "poison" in (getattr(finding, "title", "") or "").lower():
        return "Hidden instructions can change how the AI behaves."
    if sev in ("CRITICAL", "HIGH"):
        return "This should be treated as a priority for security review."
    return "Review and harden this area before production use."


def _finding_flow_ids(taint_graph: Optional[Dict[str, Any]], finding_id: str) -> List[str]:
    """Flow ids from the existing taint graph that already cite this finding."""
    if not taint_graph or not finding_id:
        return []
    out: List[str] = []
    for fl in taint_graph.get("flows") or []:
        if finding_id in (fl.get("finding_ids") or []):
            fid = fl.get("id")
            if fid:
                out.append(str(fid))
    return out


def _evidence_table(finding: Any) -> str:
    """Render recorded evidence rows without inventing locations."""
    rows = []
    for ev in getattr(finding, "evidence", None) or []:
        loc = getattr(ev, "file", "") or ""
        if getattr(ev, "line", None):
            loc = f"{loc}:{ev.line}"
        desc = getattr(ev, "description", "") or ""
        rows.append(
            f"<tr><td class='finding-loc'>{_e(loc or '—')}</td>"
            f"<td>{_e(desc)}</td></tr>"
        )
    if not rows:
        return ""
    return (
        "<div class='table-wrap'><table><thead><tr>"
        "<th>Location</th><th>Evidence</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table></div>"
    )


def _finding_detail_html(
    finding: Any,
    taint_by_pat: Dict[str, List[str]],
    *,
    show_instance_label: bool = False,
    group_key: str = "",
    taint_graph: Optional[Dict[str, Any]] = None,
) -> str:
    """Finding body: provenance, evidence, and a link to the matching taint path."""
    meta = getattr(finding, "metadata", None) or {}
    fid = str(getattr(finding, "id", "") or "")
    parts: List[str] = []

    if show_instance_label and group_key:
        label = _instance_label(finding, group_key)
        parts.append(f"<strong>{_e(label)}</strong>")

    if fid:
        parts.append(f"<div class='finding-id'>{_e(fid)}</div>")

    pills = []
    conf = meta.get("confidence") or getattr(finding, "confidence", "")
    if conf:
        pills.append(f"<span class='src-badge'>confidence: {_e(conf)}</span>")
    kind = meta.get("taint_kind") or getattr(finding, "taint_kind", "")
    if kind:
        pills.append(f"<span class='src-badge'>taint: {_e(kind)}</span>")
    if meta.get("confirmed_by_taint") or getattr(finding, "confirmed_by_taint", False):
        pills.append("<span class='src-badge'>path confirmed</span>")
    src_file = meta.get("source_file") or getattr(finding, "source_file", None)
    src_line = meta.get("source_line") or getattr(finding, "source_line", None)
    sink_file = meta.get("sink_file") or getattr(finding, "sink_file", None) or getattr(finding, "file", None)
    sink_line = meta.get("sink_line") or getattr(finding, "sink_line", None) or getattr(finding, "line", None)
    if src_file:
        loc = f"{src_file}:{src_line}" if src_line else str(src_file)
        pills.append(f"<span class='src-badge'>source {_e(loc)}</span>")
    if sink_file:
        loc = f"{sink_file}:{sink_line}" if sink_line else str(sink_file)
        pills.append(f"<span class='src-badge'>sink {_e(loc)}</span>")
    if pills:
        parts.append(f"<div class='ev-meta'>{''.join(pills)}</div>")

    parts.append(
        f"<div class='finding-desc'><strong>What we found:</strong> {_e(_plain_title(finding))}</div>"
    )

    loc = _finding_loc_str(finding)
    if loc:
        parts.append(
            f"<div class='finding-loc'><strong>Where:</strong> {_e(loc)}</div>"
        )

    ev_table = _evidence_table(finding)
    if ev_table:
        parts.append(ev_table)

    parts.append(
        f"<div class='finding-desc'><strong>Why it matters:</strong> {_e(_why_it_matters(finding))}</div>"
    )

    taint_hops = list(meta.get("taint_path") or [])
    hop_html = _hop_list_html([str(h) for h in taint_hops])
    if hop_html:
        parts.append(
            "<div class='finding-desc'><strong>Taint hops:</strong></div>"
            f"<div class='path-chain'>{hop_html}</div>"
        )
    else:
        paths = taint_by_pat.get(fid, [])[:2]
        if paths:
            for p in paths:
                parts.append(f"<div class='path-chain'>{_e(p)}</div>")

    flow_ids = _finding_flow_ids(taint_graph, fid)
    if flow_ids:
        parts.append(
            f"<button type='button' data-show-taint-flow='{_e(flow_ids[0])}'>"
            "Show confirmed path</button>"
        )

    rem = meta.get("remediation")
    if rem:
        short = str(rem).strip().split(". ")[0].strip()
        if short and not short.endswith("."):
            short += "."
        parts.append(
            f"<div class='finding-desc'><strong>What to do:</strong> {_e(short)}</div>"
        )

    return f"<div class='sub-finding'>{''.join(parts)}</div>"


def _findings_section(
    security_findings: list,
    crossfile_taint: Any = None,
    taint_graph: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Render security findings as grouped collapsible details.

    Pattern (PAT-*) and taint-confirmed findings are included here with path
    details in the dropdown — no separate Pattern/Taint sections.
    """
    if not security_findings:
        return (
            "<div class='section' id='findings'><h2>Security Findings</h2>"
            "<div class='empty'>No security findings detected.</div></div>"
        )

    taint_by_pat = _taint_paths_by_pattern(crossfile_taint)
    groups = _group_findings(security_findings)
    cards = ""
    for group_key, group, sev in groups:
        color = _SEV_COLOR.get(sev, "#94a3b8")
        count = len(group)
        count_badge = f"<span class='finding-count'>×{count}</span>" if count > 1 else ""
        src = _source_badge(group[0].category)
        summary_title = _display_group_title(group_key, group)

        if count == 1:
            body_inner = _finding_detail_html(
                group[0], taint_by_pat, taint_graph=taint_graph
            )
        else:
            body_inner = (
                f"<div class='finding-desc'>"
                f"Found in {count} places — open each item below.</div>"
            )
            for f in group:
                body_inner += _finding_detail_html(
                    f,
                    taint_by_pat,
                    show_instance_label=True,
                    group_key=group_key,
                    taint_graph=taint_graph,
                )

        cards += (
            f"<details class='finding' style='border-left-color:{color}'>"
            f"<summary>{_CHEVRON}"
            f"<span class='sev-badge' style='background:{color}22;color:{color}'>{_e(sev)}</span>"
            f"<span class='finding-title'>{_e(summary_title)}</span>"
            f"{src}{count_badge}</summary>"
            f"<div class='f-body'>{body_inner}</div></details>"
        )

    total = len(security_findings)
    grouped = len(groups)
    heading = (
        f"Security Findings ({grouped} groups · {total} total)"
        if grouped < total
        else f"Security Findings ({total})"
    )
    howto = _how_to_read(
        "Each card is a security finding. Severity is on the left. "
        "Confidence and source/sink labels come from the analyzer. "
        "“Show taint path” opens the matching confirmed DataFlow only — "
        "call-graph reachability is not treated as value taint."
    )
    return f"<div class='section' id='findings'><h2>{heading}</h2>{howto}{cards}</div>"


def _analyzer_table_section(
    title: str,
    rows: List[Tuple[str, ...]],
    headers: List[str],
) -> str:
    """Generic table section for analyzer results."""
    if not rows:
        return ""
    head = "".join(f"<th>{_e(h)}</th>" for h in headers)
    body = ""
    for row in rows:
        cells = "".join(f"<td>{c}</td>" for c in row)
        body += f"<tr>{cells}</tr>"
    return (
        f"<div class='section'><h2>{_e(title)} ({len(rows)})</h2>"
        f"<div class='table-wrap'><table><thead><tr>{head}</tr></thead>"
        f"<tbody>{body}</tbody></table></div></div>"
    )


def _sensitive_section(sensitive_exposures: Any) -> str:
    """Sensitive data exposure rows."""
    if sensitive_exposures is None:
        return ""
    exposures = getattr(sensitive_exposures, "sensitive_exposures", None) or []
    rows = []
    for ex in exposures[:30]:
        sev = str(getattr(ex, "risk", "medium")).upper()
        color = _SEV_COLOR.get(sev, "#94a3b8")
        loc = getattr(ex, "file", "") or ""
        if getattr(ex, "line", None):
            loc = f"{loc}:{ex.line}"
        rows.append(
            (
                _e(getattr(ex, "variable", "secret")),
                f"<span class='sev-badge' style='background:{color}22;color:{color}'>{_e(sev)}</span>",
                _e(str(getattr(ex, "sink", ""))[:120]),
                f"<span class='finding-loc'>{_e(loc)}</span>",
            )
        )
    return _analyzer_table_section(
        "Sensitive Data Exposures",
        rows,
        ["Name", "Severity", "Sink / Evidence", "Location"],
    )


def _prompt_injection_section(prompt_injection_risks: Any) -> str:
    """Prompt injection analyzer rows."""
    if prompt_injection_risks is None:
        return ""
    risks = getattr(prompt_injection_risks, "prompt_injection_risks", None) or []
    rows = []
    for r in risks[:30]:
        sev = str(getattr(r, "severity", "medium")).upper()
        color = _SEV_COLOR.get(sev, "#94a3b8")
        loc = getattr(r, "file", "") or getattr(r, "source_file", "") or ""
        if getattr(r, "line", None):
            loc = f"{loc}:{r.line}"
        rows.append(
            (
                _e(getattr(r, "type", "prompt_injection")),
                f"<span class='sev-badge' style='background:{color}22;color:{color}'>{_e(sev)}</span>",
                _e(str(getattr(r, "evidence", ""))[:140]),
                f"<span class='finding-loc'>{_e(loc)}</span>",
            )
        )
    return _analyzer_table_section(
        "Prompt Injection Exposure",
        rows,
        ["Type", "Severity", "Evidence", "Location"],
    )


def _is_semantic_flow_graph(df: Any) -> bool:
    """True for AIBOM DataFlowGraph (architecture pattern), not taint DataFlow."""
    if getattr(df, "source", None) or getattr(df, "sink", None):
        return False
    return bool(getattr(df, "nodes", None) or getattr(df, "flow_type", None))


def _dataflow_location(df: Any) -> str:
    """Source file:line → sink file:line. Missing fields omitted, not invented."""
    sink_file = getattr(df, "file", "") or ""
    sink_line = getattr(df, "line", None)
    sink_loc = sink_file + (f":{sink_line}" if sink_line else "")
    src_file = getattr(df, "source_file", "") or ""
    src_line = getattr(df, "source_line", None)
    if src_file:
        src_loc = src_file + (f":{src_line}" if src_line else "")
        if src_loc != sink_loc:
            return f"{src_loc} → {sink_loc}" if sink_loc else src_loc
    return sink_loc


def _hop_list_html(hops: List[str]) -> str:
    """Source → intermediate hops → sink, escaped, for HTML reports."""
    clean = [str(h).strip() for h in hops if str(h).strip()]
    if not clean:
        return ""
    parts: List[str] = []
    last = len(clean) - 1
    for i, hop in enumerate(clean):
        kind = "hop-src" if i == 0 else ("hop-sink" if i == last else "hop-mid")
        parts.append(f"<span class='hop {kind}'>{_e(hop)}</span>")
    return (
        "<span class='hop-list'>"
        + "<span class='hop-arrow' aria-hidden='true'> → </span>".join(parts)
        + "</span>"
    )


def _dataflow_trace(df: Any) -> str:
    """Ordered hops from the taint DataFlow only — never architecture graphs."""
    hops = [str(h).strip() for h in (getattr(df, "hops", None) or []) if str(h).strip()]
    return _hop_list_html(hops) or "—"


def _dataflow_notes(df: Any) -> str:
    """Sanitization / confidence when present; no fabricated certainty."""
    bits: List[str] = []
    if getattr(df, "sanitized", False):
        bits.append("sanitized")
    conf = str(getattr(df, "confidence", "") or "").strip()
    if conf:
        bits.append(f"confidence:{conf}")
    return ", ".join(bits) if bits else "—"


def _dataflow_table_row(df: Any) -> Tuple[str, ...]:
    """Taint DataFlow cells: risk, source, sink, category, location, trace, notes."""
    if _is_semantic_flow_graph(df):
        return ()

    risk = str(getattr(df, "risk", "flow"))
    cat = str(getattr(df, "sink_category", "") or "") or "—"
    loc = _dataflow_location(df)
    return (
        _e(risk),
        _e(str(getattr(df, "source", ""))[:100]),
        _e(str(getattr(df, "sink", ""))[:80]),
        _e(cat),
        f"<span class='finding-loc'>{_e(loc)}</span>",
        f"<div class='path-chain'>{_dataflow_trace(df)}</div>",
        _e(_dataflow_notes(df)),
    )


def _iter_dataflow_rows(dataflow_analysis: Any, aibom_dataflows: list) -> list:
    """Taint findings only. Architecture graphs stay in the Mermaid section."""
    if dataflow_analysis is None:
        return []
    return list(getattr(dataflow_analysis, "data_flows", None) or [])


def _dataflow_coverage_notice(dataflow_analysis: Any) -> str:
    """Coverage limitations — not findings, and not a complete-analysis claim."""
    from .finding_contract import coverage_from_analysis

    cov = coverage_from_analysis(dataflow_analysis)
    n = cov["unresolved_calls"]["count"]
    u = cov["unsupported_call_forms"]["count"]
    if not n and not u:
        return ""
    bits = []
    if n:
        bits.append(f"{n} unresolved tainted call(s)")
    if u:
        bits.append(f"{u} unsupported call form(s)")
    return (
        "<div class='path-card'><strong>Coverage limitations.</strong> "
        f"{_e(', '.join(bits))}. These are not findings and do not prove "
        "the application is safe. Unresolved calls are not treated as "
        "confirmed taint.</div>"
    )


def _dataflow_incomplete_notice(dataflow_analysis: Any) -> str:
    """Structured truncation notice — not mixed into finding table cells."""
    if dataflow_analysis is None or not getattr(dataflow_analysis, "incomplete", False):
        return ""
    reasons = list(getattr(dataflow_analysis, "incomplete_reasons", None) or [])
    why = ", ".join(_e(r) for r in reasons) if reasons else "worklist cap"
    return (
        "<div class='path-card'><strong>Analysis incomplete.</strong> "
        f"Taint worklist stopped early ({why}). "
        "Missing flows are not a complete negative; do not treat this "
        "result as full coverage.</div>"
    )


def _dataflow_section(dataflow_analysis: Any, aibom_dataflows: list) -> str:
    """Coverage notices only. Confirmed paths are rendered once under Taint paths."""
    notice = _dataflow_incomplete_notice(dataflow_analysis) + _dataflow_coverage_notice(
        dataflow_analysis
    )
    if not notice:
        return ""
    return (
        f"<div class='section' id='data-coverage'><h2>Analysis coverage</h2>"
        f"{notice}</div>"
    )


def _policy_section(policy: Any) -> str:
    """Policy evaluation pass/fail and rule messages."""
    if policy is None:
        return (
            "<div class='section'><h2>Policy Evaluation</h2>"
            "<div class='empty'>No policy.yaml evaluated.</div></div>"
        )
    passed = bool(getattr(policy, "passed", True))
    status = (
        "<span class='policy-pass'>PASSED</span>"
        if passed
        else "<span class='policy-fail'>FAILED</span>"
    )
    cards = ""
    for r in getattr(policy, "results", []) or []:
        ok = bool(getattr(r, "passed", True))
        cls = "policy-pass" if ok else "policy-fail"
        label = "PASS" if ok else "FAIL"
        cards += (
            f"<div class='path-card'>"
            f"<strong class='{cls}'>{label}</strong> "
            f"<code>{_e(getattr(r, 'rule_id', 'rule'))}</code> — "
            f"{_e(getattr(r, 'message', ''))}</div>"
        )
    empty = "<div class='empty'>No rule results.</div>"
    return (
        f"<div class='section'><h2>Policy Evaluation — {status}</h2>"
        f"{cards or empty}</div>"
    )


def _llm_verification_section(llm_verification: Any) -> str:
    """Optional LLM verification overlay (does not alter static findings)."""
    if llm_verification is None:
        return ""
    verifications = getattr(llm_verification, "verifications", []) or []
    top_errors = [str(e) for e in (getattr(llm_verification, "errors", None) or []) if e]
    if not verifications and not top_errors:
        return ""

    def _verdict_of(v: Any) -> str:
        explicit = getattr(v, "verdict", "") or ""
        if explicit:
            return str(explicit).upper()
        if getattr(v, "error", None):
            return "ERROR"
        if getattr(v, "verified", False) and not getattr(v, "false_positive", False):
            return "VERIFIED"
        if getattr(v, "false_positive", False):
            return "FALSE_POSITIVE"
        return "INCONCLUSIVE"

    cards = ""
    for v in verifications:
        verdict = _verdict_of(v)
        reason = getattr(v, "reasoning", "") or getattr(v, "false_positive_reason", "") or ""
        extra = getattr(v, "attack_scenario", "") if verdict == "VERIFIED" else ""
        err = getattr(v, "error", "") or ""
        model = getattr(v, "model_used", "") or ""
        body = extra or reason or err
        cards += (
            f"<div class='path-card'>"
            f"<strong>{_e(getattr(v, 'finding_id', ''))}</strong> {_e(verdict)}"
            f"{' — ' + _e(model) if model else ''}"
            f"<div class='finding-desc'>{_e(body)}</div>"
            f"</div>"
        )
    for err in top_errors:
        if any(getattr(v, "error", "") == err for v in verifications):
            continue
        cards += (
            f"<div class='path-card'>"
            f"<strong>ERROR</strong>"
            f"<div class='finding-desc'>{_e(err)}</div>"
            f"</div>"
        )
    summary = (
        f"{getattr(llm_verification, 'findings_verified', 0)} verified · "
        f"{getattr(llm_verification, 'findings_dismissed', 0)} false positives · "
        f"{getattr(llm_verification, 'findings_inconclusive', 0)} inconclusive · "
        f"{getattr(llm_verification, 'findings_errored', 0)} errors · "
        f"{getattr(llm_verification, 'api_calls_made', 0)} API calls"
    )
    return (
        f"<div class='section'><h2>LLM Verification</h2>"
        f"<div class='hdr-sub' style='margin-bottom:.75rem'>{_e(summary)}</div>"
        f"{cards}</div>"
    )


def _mermaid_section(diagram_src: str, extra_diagrams: Optional[List[Tuple[str, str]]] = None) -> str:
    """Optional AIBOM semantic patterns only — not a second architecture graph."""
    extras = [(t, s) for t, s in (extra_diagrams or []) if s]
    if not extras:
        return ""
    parts = [
        "<div class='section' id='semantic-patterns'>",
        "<h2>Semantic flow patterns</h2>",
        _how_to_read(
            "AIBOM semantic flow patterns recorded during discovery. "
            "These are not confirmed value-taint paths."
        ),
    ]
    for title, src in extras:
        parts.append(f"<h3>{_e(title)}</h3>")
        parts.append(f"<div class='mmd-wrap'><div class='mermaid'>{_e(src)}</div></div>")
    parts.append("</div>")
    return "".join(parts)


def _payload_with_line_numbers(payload_text: str) -> str:
    """Render a payload string as a code block with line numbers."""
    lines = payload_text.splitlines()
    rows = ""
    for i, line in enumerate(lines, 1):
        rows += (
            f"<div class='pl'><span class='ln'>{i}</span>"
            f"<span class='lc'>{_e(line)}</span></div>"
        )
    return f"<div class='payload-block'>{rows}</div>"


def _exploit_section(
    payloads: List["ExploitPayload"],
    verification_map: Dict[str, "VerificationResult"],
) -> str:
    """Render exploit payloads behind a security-gated details block."""
    if not payloads:
        return ""

    _VERDICT_COLORS = {"confirmed": "#22c55e", "likely": "#f59e0b", "uncertain": "#94a3b8"}
    _VERDICT_ICONS = {"confirmed": "✔", "likely": "~", "uncertain": "?"}
    _VERDICT_LABELS = {"confirmed": "CONFIRMED", "likely": "LIKELY", "uncertain": "UNCERTAIN"}

    cards = ""
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    for p in sorted(payloads, key=lambda x: sev_order.get(x.severity, 9)):
        sev = p.severity.upper()
        color = _SEV_COLOR.get(sev, "#94a3b8")
        loc = p.target_file + (f":{p.target_line}" if p.target_line else "")
        cvss = p.cvss_vector.split("/")[0] if "/" in p.cvss_vector else p.cvss_vector

        vr = verification_map.get(p.finding_id)
        verdict_html = ""
        if vr:
            vc = _VERDICT_COLORS.get(vr.verdict, "#94a3b8")
            vi = _VERDICT_ICONS.get(vr.verdict, "?")
            vl = _VERDICT_LABELS.get(vr.verdict, vr.verdict.upper())
            ev_for_html = "".join(
                f"<div class='verify-ev'><span style='color:#22c55e'>+</span>"
                f"<span>{_e(ev)}</span></div>"
                for ev in vr.evidence_for
            )
            ev_against_html = "".join(
                f"<div class='verify-ev'><span style='color:#ef4444'>−</span>"
                f"<span>{_e(ev)}</span></div>"
                for ev in vr.evidence_against
            )
            verdict_html = (
                f"<div class='verdict-box' style='border:1px solid {vc}33'>"
                f"<div style='font-size:.8rem;font-weight:700;color:{vc};margin-bottom:.4rem'>"
                f"{_e(vi)} {_e(vl)} — {vr.confidence}% confidence</div>"
                f"{ev_for_html}{ev_against_html}</div>"
            )

        steps_html = "".join(
            f"<li style='font-size:.8rem;color:var(--muted);margin-top:.3rem;line-height:1.4'>"
            f"{_e(s)}</li>"
            for s in p.reproduction_steps
        )
        steps_block = (
            f"<details style='margin-top:.25rem'>"
            f"<summary style='font-size:.8rem;color:var(--accent);cursor:pointer;list-style:none'>"
            f"&#9658; Reproduction steps</summary>"
            f"<ol style='padding-left:1.4rem;margin-top:.5rem'>{steps_html}</ol></details>"
            if steps_html
            else ""
        )

        cards += (
            f"<details class='exploit-card'><summary>{_CHEVRON}"
            f"<span class='sev-badge' style='background:{color}22;color:{color}'>{_e(sev)}</span>"
            f"<span class='finding-title'>{_e(p.title)}</span>"
            f"<span style='font-size:.72rem;font-family:monospace;color:var(--muted);"
            f"flex-shrink:0;margin-top:.15rem'>{_e(loc)}</span></summary>"
            f"<div class='exploit-body'>"
            f"<div class='exploit-meta'>"
            f"<span class='exploit-meta-pill'><strong>ID</strong> {_e(p.finding_id)}</span>"
            f"<span class='exploit-meta-pill'><strong>Source</strong> {_e(p.source_type)}</span>"
            f"<span class='exploit-meta-pill'><strong>Sink</strong> {_e(p.sink_type)}</span>"
            f"<span class='exploit-meta-pill'><strong>CVSS</strong> {_e(cvss)}</span>"
            f"</div>"
            f"<div class='exploit-desc'>{_e(p.expected_behavior)}</div>"
            f"{_payload_with_line_numbers(p.payload)}"
            f"{verdict_html}{steps_block}</div></details>"
        )

    gate_chevron = (
        "<svg class='gate-chevron' width='14' height='14' viewBox='0 0 24 24' fill='none' "
        "stroke='currentColor' stroke-width='2.5'><polyline points='9 18 15 12 9 6'/></svg>"
    )
    warning = (
        "<div class='gate-warning'>"
        "These payloads are for authorized security testing only. "
        "Do not use against systems you do not own or lack permission to test."
        "</div>"
    )
    return (
        f"<details class='exploit-gate'><summary>"
        f"<span class='gate-lock'>🔒</span>"
        f"<span class='gate-title'>Security Team Only — Exploit Payloads ({len(payloads)})</span>"
        f"<span class='gate-subtitle'>click to expand</span>{gate_chevron}</summary>"
        f"<div class='gate-body'>{warning}{cards}</div></details>"
    )


def _downloads_section(out_path: Path) -> str:
    """Link only sibling artifacts that exist in the output directory."""
    catalog = [
        ("aitrace-risk-report.md", "Risk Report (Markdown)"),
        ("aitrace-cyclonedx.json", "CycloneDX SBOM"),
        ("aitrace-spdx.json", "SPDX Document"),
        ("aitrace-component-diagram.mmd", "Architecture Diagram"),
        ("aitrace-risk-report.json", "Risk Report (JSON)"),
        ("aitrace-findings.json", "Findings (JSON)"),
        ("aitrace-exploits.json", "Exploit Payloads"),
        ("aitrace-rag-poison-payload.txt", "RAG Poison Payload"),
        ("aitrace-architecture-graph.json", "Architecture Graph (JSON)"),
        ("aitrace-architecture-graph.mmd", "Architecture Graph (Mermaid)"),
    ]
    existing = [(fn, label) for fn, label in catalog if (out_path / fn).is_file()]
    if not existing:
        return ""
    btns = "".join(
        f"<a class='dl-btn' href='{fn}' download>{_e(label)}</a>" for fn, label in existing
    )
    return (
        f"<div class='section' id='downloads'><h2>Downloads</h2>"
        f"<div class='dl-row'>{btns}</div></div>"
    )


def _mermaid_script() -> str:
    return (
        "<script type='module'>"
        "import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs';"
        "mermaid.initialize({startOnLoad:true,theme:'neutral'});"
        "</script>"
    )


_GRAPH_KIND_COLORS = {
    "api_endpoint": "#d97706",
    "agent": "#7c3aed",
    "prompt_builder": "#0891b2",
    "llm_provider": "#2563eb",
    "embedding_model": "#16a34a",
    "vector_db": "#059669",
    "retriever": "#0d9488",
    "memory": "#9333ea",
    "tool": "#e11d48",
    "mcp_server": "#ea580c",
    "database": "#0284c7",
    "http_client": "#64748b",
    "security_control": "#15803d",
    "function": "#475569",
    "source": "#dc2626",
    "sink": "#c2410c",
    "intermediate": "#2563eb",
}

_KIND_LABELS = {
    "api_endpoint": "API",
    "agent": "Agent",
    "prompt_builder": "Prompt",
    "llm_provider": "LLM",
    "embedding_model": "Embedding",
    "retriever": "Retriever",
    "vector_db": "Vector DB",
    "memory": "Memory",
    "tool": "Tool",
    "http_client": "HTTP",
    "database": "Database",
    "mcp_server": "MCP",
    "security_control": "Control",
    "function": "Function",
    "source": "Source",
    "sink": "Sink",
    "intermediate": "Hop",
}


def _json_script(dom_id: str, payload: Any) -> str:
    """Embed JSON for the offline graph renderer."""
    text = json.dumps(payload, default=str, ensure_ascii=True)
    text = text.replace("<", "\\u003c")
    return f"<script type='application/json' id='{_e(dom_id)}'>{text}</script>"


def _graph_fallback_list(graph: Dict[str, Any], *, taint: bool = False) -> str:
    """Text list so the report remains usable without the SVG."""
    if taint:
        flows = list(graph.get("flows") or [])
        if not flows:
            return "<div class='empty'>No confirmed value-taint flows to list.</div>"
        items = []
        for fl in flows[:40]:
            loc = f"{fl.get('source_file') or '?'}:{fl.get('source_line') or '—'}"
            sink = f"{fl.get('sink_file') or '?'}:{fl.get('sink_line') or '—'}"
            items.append(
                "<li>"
                f"{_e(fl.get('sink_category') or 'flow')} "
                f"{_e(fl.get('taint_kind') or '')} "
                f"{_e(loc)} → {_e(sink)}"
                f" role={_e(fl.get('sink_arg_role') or 'n/a')}"
                f" findings={_e(','.join(fl.get('finding_ids') or []) or 'none')}"
                "</li>"
            )
        return f"<ul class='graph-fallback'>{''.join(items)}</ul>"
    nodes = list(graph.get("nodes") or [])
    if not nodes:
        return "<div class='empty'>No architecture components observed in source.</div>"
    items = []
    for n in nodes[:60]:
        loc = n.get("file") or ""
        if n.get("line"):
            loc = f"{loc}:{n.get('line')}"
        items.append(
            f"<li>{_e(n.get('kind'))}: {_e(n.get('label'))}"
            f"{(' @ ' + _e(loc)) if loc else ''} — {_e(n.get('evidence') or '')}</li>"
        )
    edges = list(graph.get("edges") or [])
    for e in edges[:40]:
        loc = ""
        if e.get("file"):
            loc = str(e.get("file"))
            if e.get("line"):
                loc = f"{loc}:{e.get('line')}"
        items.append(
            f"<li>edge {_e(e.get('relationship') or e.get('label') or 'rel')} "
            f"{_e(e.get('source'))} → {_e(e.get('target'))} "
            f"[{_e(e.get('classification') or e.get('evidence_status'))}]"
            f"{(' @ ' + _e(loc)) if loc else ''}</li>"
        )
    return f"<ul class='graph-fallback'>{''.join(items)}</ul>"


def _legend_html(kinds: List[str]) -> str:
    chips = []
    for k in kinds:
        color = _GRAPH_KIND_COLORS.get(k, "#94a3b8")
        label = _KIND_LABELS.get(k, k.replace("_", " "))
        chips.append(
            f"<span><i class='graph-swatch' style='background:{color}'></i>{_e(label)}</span>"
        )
    return f"<div class='graph-legend'>{''.join(chips)}</div>"


def _architecture_graph_section(
    graph: Optional[Dict[str, Any]],
    *,
    embedded: bool = False,
) -> str:
    """Interactive architecture graph plus a text fallback."""
    graph = graph or {"nodes": [], "edges": [], "stats": {}}
    stats = graph.get("stats") or {}
    n_n = stats.get("node_count", len(graph.get("nodes") or []))
    n_e = stats.get("edge_count", len(graph.get("edges") or []))
    kinds = sorted({str(n.get("kind") or "") for n in graph.get("nodes") or [] if n.get("kind")})
    empty = not graph.get("nodes")
    body = (
        "<div class='empty'>No AI architecture components were identified from "
        "source evidence. Package inventory is listed under AI Components.</div>"
        if empty
        else (
            "<div class='graph-shell'>"
            "<div class='graph-toolbar'>"
            "<input data-graph-search='arch' placeholder='Search component' aria-label='Search architecture'>"
            "<select data-graph-filter='arch' aria-label='Filter architecture type'>"
            "<option value=''>All types</option>"
            + "".join(f"<option value='{_e(k)}'>{_e(k)}</option>" for k in kinds)
            + "</select>"
            "<button type='button' data-graph-reset='arch'>Reset view</button>"
            "</div>"
            "<svg class='graph-canvas' id='aitrace-arch-svg' role='img' "
            "aria-label='AI architecture graph'></svg>"
            "<div class='graph-detail' id='aitrace-arch-detail'>Select a node or edge for evidence.</div>"
            "</div>"
        )
    )
    howto = _how_to_read(
        f"<ul><li>Components from source ({n_n} nodes · {n_e} edges). "
        "Solid edges are AST or framework invocations; dashed edges are structural or inferred.</li>"
        "<li>Search and type filter hide nodes; they do not add edges.</li>"
        "<li>This is not a taint graph. Architecture reachability is not taint confirmation.</li></ul>"
    )
    inner = howto + _legend_html(kinds) + body + _graph_fallback_list(graph) + _json_script(
        "aitrace-arch-data", graph
    )
    if embedded:
        return inner
    return (
        "<div class='section' id='architecture-graph'>"
        "<h2>AI application architecture</h2>"
        + inner
        + "</div>"
    )


def _taint_path_table(flow: Dict[str, Any]) -> str:
    """Always-visible 3-column path: location and what the value is doing."""
    steps = taint_steps(flow)
    if not steps:
        return ""
    rows: List[str] = []
    titles = {"source": "Source", "sink": "Sink", "intermediate": "Hop"}
    for st in steps:
        file = str(st.get("file") or "").replace("\\", "/").split("/")[-1]
        loc = f"{file}:{st.get('line')}" if st.get("line") else file
        func = str(st.get("function") or "")
        where = _e(loc)
        if func:
            where += f"<div class='taint-fn'>{_e(func)}</div>"
        kind = str(st.get("kind") or "")
        if kind == "source":
            moving = str(st.get("value") or "untrusted value")
        elif kind == "sink":
            bits = []
            if st.get("edge_in") and str(st.get("edge_in")) not in {"n/a", "arg"}:
                bits.append(f"passed as {st['edge_in']}")
            if st.get("use"):
                bits.append(f"used at {st['use']}")
            moving = ", ".join(bits) or str(st.get("value") or "sink")
        else:
            incoming = str(st.get("edge_in") or "")
            moving = f"passed as {incoming}" if incoming and incoming not in {"n/a", "arg"} else str(
                st.get("value") or ""
            )
        rows.append(
            "<tr>"
            f"<td>{_e(titles.get(kind, kind))}</td>"
            f"<td>{where}</td>"
            f"<td><code>{_e(moving)}</code></td>"
            "</tr>"
        )
    return (
        "<div class='taint-path-table'><table>"
        "<thead><tr><th></th><th>Location</th><th>Value</th></tr></thead>"
        "<tbody>"
        + "".join(rows)
        + "</tbody></table></div>"
    )


def _taint_flow_panel(flow: Dict[str, Any], *, active: bool) -> str:
    """One confirmed DataFlow: sentence, location diagram, compact path table."""
    fid = str(flow.get("id") or "")
    cls = "taint-flow-panel is-active" if active else "taint-flow-panel"
    svg = taint_flow_svg(flow, svg_id=f"taint-{fid}")
    story = taint_narrative_html(flow)
    pills = [
        f"<span class='taint-pill'>confidence {_e(flow.get('confidence') or 'n/a')}</span>"
    ]
    findings = ", ".join(flow.get("finding_ids") or [])
    if findings:
        pills.append(f"<span class='taint-pill'>{_e(findings)}</span>")
    return (
        f"<div class='{cls}' data-taint-panel='{_e(fid)}'>"
        + (f"<p class='taint-story'>{story}</p>" if story else "")
        + svg
        + "<p class='taint-caption'>Each box is a location (file, function, line). "
        "The name on the arrow is how the value is passed into the next function.</p>"
        + _taint_path_table(flow)
        + "<div class='taint-pills'>"
        + "".join(pills)
        + "</div></div>"
    )


def _taint_graph_section(graph: Optional[Dict[str, Any]]) -> str:
    """Finding-centric taint paths: one confirmed DataFlow at a time."""
    graph = graph or {"flows": [], "nodes": [], "edges": []}
    n_f = int(graph.get("flow_count") or 0)
    n_s = int(graph.get("unique_sink_count") or 0)
    cats = sorted({str(f.get("sink_category") or "") for f in graph.get("flows") or [] if f.get("sink_category")})
    kinds = sorted({str(f.get("taint_kind") or "") for f in graph.get("flows") or [] if f.get("taint_kind")})
    empty = n_f == 0
    struct = list(graph.get("structural_reachability") or [])
    struct_html = ""
    if struct:
        items = "".join(
            f"<li>reachability {_e(s.get('source'))} → {_e(s.get('sink'))} "
            "(not value-taint)</li>"
            for s in struct[:8]
        )
        struct_html = (
            "<div class='hdr-sub'>Call-graph reachability (not confirmed taint)</div>"
            f"<ul class='graph-fallback'>{items}</ul>"
        )
    flows = list(graph.get("flows") or [])
    first_id = str(flows[0].get("id") or "") if flows else ""
    options = []
    panels = []
    for i, f in enumerate(flows):
        fid = str(f.get("id") or "")
        selected = " selected" if fid == first_id else ""
        findings = ",".join(f.get("finding_ids") or []) or "no finding id"
        options.append(
            f"<option value='{_e(fid)}'{selected}>"
            f"{_e(f.get('sink_category') or 'flow')} "
            f"{_e(f.get('sink_file') or '')}:{_e(f.get('sink_line') or '—')} "
            f"({_e(findings)})</option>"
        )
        panels.append(_taint_flow_panel(f, active=(fid == first_id)))
    body = (
        "<div class='empty'>No confirmed value-taint flows were recorded.</div>"
        if empty
        else (
            "<div class='graph-shell'>"
            "<div class='graph-toolbar'>"
            "<select data-taint-flow='taint' aria-label='Select taint flow'>"
            + "".join(options)
            + "</select>"
            "<select data-graph-filter='taint' aria-label='Filter sink category'>"
            "<option value=''>All sink categories</option>"
            + "".join(f"<option value='{_e(k)}'>{_e(k)}</option>" for k in cats)
            + "</select>"
            "<select data-taint-kind='taint' aria-label='Filter taint kind'>"
            "<option value=''>All taint kinds</option>"
            + "".join(f"<option value='{_e(k)}'>{_e(k)}</option>" for k in kinds)
            + "</select>"
            "<button type='button' data-graph-reset='taint'>Reset view</button>"
            "</div>"
            "<div id='aitrace-taint-panels'>"
            + "".join(panels)
            + "</div>"
            "<svg class='graph-canvas' id='aitrace-taint-svg' hidden role='img' "
            "aria-label='Taint-flow graph'></svg>"
            "<div class='graph-detail' id='aitrace-taint-detail' hidden>"
            "Source, sink, hops, and confidence for the selected flow.</div>"
            "</div>"
        )
    )
    howto = _how_to_read(
        f"<ul>"
        f"<li>These are confirmed attack paths: an untrusted value was tracked from a "
        f"source, through parameters, to a sink ({n_f} paths · {n_s} unique sinks).</li>"
        "<li>Architecture (above) only shows that a call exists. This section shows "
        "the value moving.</li>"
        "<li>The box is the location (file, function, line). The name on the arrow is "
        "the parameter, not the function.</li>"
        "</ul>"
    )
    return (
        "<div class='section' id='taint-flow-graph'>"
        "<h2>Confirmed taint paths</h2>"
        + howto
        + body
        + "<details class='howto'><summary>All confirmed flows</summary>"
        + _graph_fallback_list(graph, taint=True)
        + "</details>"
        + struct_html
        + _json_script("aitrace-taint-data", graph)
        + "</div>"
    )


_GRAPH_JS = r"""
<script>
(function(){
  var KIND_ORDER=["api_endpoint","agent","prompt_builder","llm_provider","embedding_model","retriever","vector_db","memory","tool","mcp_server","database","http_client","security_control","function","source","intermediate","sink","other"];
  function parse(id){
    var el=document.getElementById(id);
    if(!el) return null;
    try{return JSON.parse(el.textContent||"{}");}catch(e){return null;}
  }
  var COL_GAP=200, ROW_GAP=86, LABEL_MAX=20, CHAR_W=7.1;
  function clip(s,n){
    s=String(s||"");
    return s.length>n? s.slice(0,n-1)+"…": s;
  }
  function shortLabel(s){
    return clip(s, LABEL_MAX);
  }
  function wrapWords(s,n){
    s=String(s||"").trim();
    if(s.length<=n) return s? [s]: [];
    var i=s.lastIndexOf(" ", n);
    if(i>=Math.floor(n/2)) return [s.slice(0,i).trim(), clip(s.slice(i).trim(), n)];
    var u=s.lastIndexOf("_", n);
    if(u>=Math.floor(n/3)) return [clip(s.slice(0,u), n), clip(s.slice(u+1), n)];
    return [clip(s, n)];
  }
  function labelLines(s){
    s=String(s||"");
    var lines;
    if(s.indexOf("::")>=0){
      var p=s.split("::");
      lines=[p[0].split("/").pop(), p.slice(1).join("::")];
    } else {
      var c=s.lastIndexOf(":");
      var head=c>0? s.slice(0,c): "";
      if(c>0 && s.indexOf("://")<0 && head.indexOf(" ")===-1) lines=[head.split("/").pop(), s.slice(c+1)];
      else lines=wrapWords(s, LABEL_MAX);
    }
    return lines.filter(Boolean).slice(0,2).map(function(x){return clip(x, LABEL_MAX);});
  }
  function esc(s){
    return String(s||"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
  }
  function layout(nodes, kinds){
    kinds.sort(function(a,b){
      var ia=KIND_ORDER.indexOf(a), ib=KIND_ORDER.indexOf(b);
      if(ia<0) ia=80; if(ib<0) ib=80;
      return ia-ib;
    });
    var cols={};
    kinds.forEach(function(k,i){cols[k]=i;});
    var buckets={};
    nodes.forEach(function(n){
      var k=n.kind||n.role||"other";
      (buckets[k]=buckets[k]||[]).push(n);
    });
    var left=Math.floor(COL_GAP/2)+8, top=22;
    var pos={};
    Object.keys(buckets).forEach(function(k){
      var col=cols[k]!=null?cols[k]:kinds.length-1;
      var list=buckets[k];
      list.forEach(function(n,i){
        pos[n.id]={x:left+col*COL_GAP, y:top+i*ROW_GAP, n:n};
      });
    });
    return pos;
  }
  function colors(){return {
    api_endpoint:"#d97706",agent:"#7c3aed",prompt_builder:"#0891b2",llm_provider:"#2563eb",
    embedding_model:"#16a34a",vector_db:"#059669",retriever:"#0d9488",memory:"#9333ea",
    tool:"#e11d48",mcp_server:"#ea580c",database:"#0284c7",http_client:"#64748b",
    security_control:"#15803d",function:"#475569",source:"#dc2626",sink:"#c2410c",
    intermediate:"#2563eb",other:"#64748b"
  };}
  function render(svg, data, opts){
    if(!svg||!data) return;
    var nodes=(data.nodes||[]).slice(0,80);
    var edges=(data.edges||[]).slice(0,160);
    var pos={};
    var C=colors();
    var selected=null, filter="", search="", flowFilter="";
    var vx=0,vy=0,scale=1,drag=null;
    function visible(n){
      if(filter && (n.kind||n.role)!==filter) return false;
      if(search && (n.label||"").toLowerCase().indexOf(search)<0 && (n.id||"").toLowerCase().indexOf(search)<0) return false;
      if(flowFilter){
        var hit=false;
        (data.flows||[]).forEach(function(f){
          if(f.id===flowFilter && (f.path_node_ids||[]).indexOf(n.id)>=0) hit=true;
        });
        if(!hit) return false;
      }
      return true;
    }
    function draw(){
      var visN=nodes.filter(visible);
      var visKinds=[];
      visN.forEach(function(n){
        var k=n.kind||n.role||"other";
        if(visKinds.indexOf(k)<0) visKinds.push(k);
      });
      pos=layout(visN, visKinds);
      var ids={}; visN.forEach(function(n){ids[n.id]=1;});
      var visE=edges.filter(function(e){
        if(!ids[e.source]||!ids[e.target]) return false;
        if(flowFilter && e.flow_id && e.flow_id!==flowFilter) return false;
        return true;
      });
      var parts=["<g transform='translate("+vx+","+vy+") scale("+scale+")'>"];
      visE.forEach(function(e){
        var a=pos[e.source], b=pos[e.target];
        if(!a||!b) return;
        var hot=selected && (selected===e.source||selected===e.target||selected===e.flow_id);
        var cls=e.classification||"";
        var st=e.evidence_status||"";
        var dashed=cls==="STRUCTURAL"||cls==="INFERRED"||st==="structural"||st==="inferred";
        var dash=dashed?" stroke-dasharray='5 4'":"";
        parts.push("<line x1='"+a.x+"' y1='"+a.y+"' x2='"+b.x+"' y2='"+b.y+
          "' stroke='"+(hot?"#1d4ed8":"#94a3b8")+"' stroke-width='"+(hot?2.2:1.15)+"'"+dash+"/>");
      });
      visN.forEach(function(n){
        var p=pos[n.id]; if(!p) return;
        var k=n.kind||n.role||"other";
        var hot=selected===n.id;
        var full=n.label||n.id;
        var lines=labelLines(full);
        var tw=40;
        lines.forEach(function(line){ tw=Math.max(tw, line.length*CHAR_W+12); });
        tw=Math.min(tw, COL_GAP-16);
        var th=lines.length? lines.length*14+6: 0;
        parts.push("<g data-nid='"+esc(n.id)+"' style='cursor:pointer'>");
        parts.push("<title>"+esc(full)+"</title>");
        parts.push("<circle cx='"+p.x+"' cy='"+p.y+"' r='"+(hot?11:8)+"' fill='"+(C[k]||C.other)+"' stroke='#ffffff' stroke-width='2'/>");
        if(th){
          parts.push("<rect x='"+(p.x-tw/2)+"' y='"+(p.y+14)+"' width='"+tw+"' height='"+th+"' rx='3' fill='#f8fafc'/>");
        }
        lines.forEach(function(line,i){
          parts.push("<text x='"+p.x+"' y='"+(p.y+28+i*14)+"' text-anchor='middle' fill='#0f172a' font-size='12' font-family='ui-sans-serif,system-ui,sans-serif'>"+esc(line)+"</text>");
        });
        parts.push("</g>");
      });
      var maxX=80, maxY=80;
      visN.forEach(function(n){
        var p=pos[n.id]; if(!p) return;
        maxX=Math.max(maxX, p.x+COL_GAP/2);
        maxY=Math.max(maxY, p.y+ROW_GAP);
      });
      var vbW=Math.max(Math.ceil(maxX+16), 640), vbH=Math.max(Math.ceil(maxY+8), 220);
      svg.removeAttribute("viewBox");
      svg.removeAttribute("preserveAspectRatio");
      svg.setAttribute("width", String(vbW));
      svg.setAttribute("height", String(vbH));
      svg.style.width=vbW+"px";
      svg.style.height=vbH+"px";
      parts.push("</g>");
      svg.innerHTML=parts.join("");
      svg.querySelectorAll("[data-nid]").forEach(function(g){
        g.addEventListener("click", function(ev){
          ev.stopPropagation();
          selected=g.getAttribute("data-nid");
          var n=nodes.filter(function(x){return x.id===selected;})[0];
          if(opts.detail && n){
            opts.detail.textContent=[
              (n.kind||n.role||"node")+": "+(n.label||n.id),
              "file: "+(n.file||"unavailable")+(n.line?(":"+n.line):""),
              "evidence: "+(n.evidence||n.detection_method||"DataFlow hop"),
              "status: "+(n.evidence_status||n.confidence||""),
              n.is_sink?("sink: "+(n.sink_category||"yes")+(n.taint_confirmed?" taint-confirmed":" unconfirmed")):""
            ].filter(Boolean).join("\n");
          }
          draw();
        });
      });
    }
    svg.addEventListener("wheel", function(e){
      if(!(e.ctrlKey||e.metaKey)) return;
      e.preventDefault();
      scale=Math.min(2.5, Math.max(0.4, scale+(e.deltaY<0?0.08:-0.08)));
      draw();
    }, {passive:false});
    svg.addEventListener("mousedown", function(e){
      drag={x:e.clientX-vx,y:e.clientY-vy};
    });
    window.addEventListener("mousemove", function(e){
      if(!drag) return;
      vx=e.clientX-drag.x; vy=e.clientY-drag.y; draw();
    });
    window.addEventListener("mouseup", function(){ drag=null; });
    function pinShell(){
      vx=0; vy=0; scale=1;
      var shell=svg.parentElement;
      if(shell){ shell.scrollLeft=0; shell.scrollTop=0; }
    }
    draw();
    return {
      setFilter: function(v){filter=v||"";pinShell();draw();},
      setSearch: function(v){search=(v||"").toLowerCase();pinShell();draw();},
      setFlow: function(v){flowFilter=v||"";selected=v||null;pinShell();
        if(opts.detail && v){
          var f=(data.flows||[]).filter(function(x){return x.id===v;})[0];
          if(f){
            opts.detail.textContent=[
              "flow "+f.id,
              "taint_kind="+f.taint_kind+" sink_arg_role="+(f.sink_arg_role||"n/a"),
              "confidence="+f.confidence+" class="+f.evidence_class,
              "source "+(f.source_file||"?")+":"+(f.source_line||"unavailable"),
              "sink "+(f.sink_file||"?")+":"+(f.sink_line||"unavailable")+" "+(f.sink||""),
              "findings: "+((f.finding_ids||[]).join(", ")||"none"),
              "hops: "+((f.hops||[]).length? (f.hops||[]).map(function(h){return (h.kind||"")+" "+(h.file||"")+":"+(h.line||"—");}).join(" | "):"source and sink only")
            ].join("\n");
          }
        }
        draw();
      },
      reset: function(){selected=null;filter="";search="";flowFilter="";pinShell();
        var sel=document.querySelector("[data-taint-flow='taint']");
        if(sel && data.flows && data.flows[0]){ sel.value=data.flows[0].id; this.setFlow(data.flows[0].id); return; }
        draw();
      }
    };
  }
  var arch=parse("aitrace-arch-data");
  var taint=parse("aitrace-taint-data");
  var archCtl=render(document.getElementById("aitrace-arch-svg"), arch, {detail:document.getElementById("aitrace-arch-detail")});
  var taintSvg=document.getElementById("aitrace-taint-svg");
  var taintCtl=(!taintSvg||taintSvg.hasAttribute("hidden"))?null:render(taintSvg, taint, {detail:document.getElementById("aitrace-taint-detail")});
  if(taintCtl && taint && taint.flows && taint.flows[0]) taintCtl.setFlow(taint.flows[0].id);
  document.querySelectorAll("[data-graph-filter='arch']").forEach(function(el){
    el.addEventListener("change", function(){ if(archCtl) archCtl.setFilter(el.value); });
  });
  document.querySelectorAll("[data-graph-search='arch']").forEach(function(el){
    el.addEventListener("input", function(){ if(archCtl) archCtl.setSearch(el.value); });
  });
  document.querySelectorAll("[data-graph-reset='arch']").forEach(function(el){
    el.addEventListener("click", function(){ if(archCtl) archCtl.reset(); });
  });
  document.querySelectorAll("[data-graph-filter='taint']").forEach(function(el){
    el.addEventListener("change", function(){ if(taintCtl) taintCtl.setFilter(el.value); });
  });
  document.querySelectorAll("[data-taint-kind='taint']").forEach(function(el){
    el.addEventListener("change", function(){
      if(!taintCtl||!taint) return;
      var k=el.value;
      if(!k){ taintCtl.setFlow(""); return; }
      var first=(taint.flows||[]).filter(function(f){return f.taint_kind===k;})[0];
      taintCtl.setFlow(first?first.id:"");
    });
  });
  document.querySelectorAll("[data-taint-flow='taint']").forEach(function(el){
    el.addEventListener("change", function(){ if(taintCtl) taintCtl.setFlow(el.value); });
  });
  document.querySelectorAll("[data-graph-reset='taint']").forEach(function(el){
    el.addEventListener("click", function(){ if(taintCtl) taintCtl.reset(); });
  });
  document.querySelectorAll("[data-show-taint-flow]").forEach(function(el){
    el.addEventListener("click", function(){
      var id=el.getAttribute("data-show-taint-flow");
      var sel=document.querySelector("[data-taint-flow='taint']");
      if(sel) sel.value=id;
      if(taintCtl) taintCtl.setFlow(id);
      var box=document.getElementById("taint-flow-graph");
      if(box) box.scrollIntoView({behavior:"smooth",block:"start"});
    });
  });
})();
</script>
"""

_OVERVIEW_JS = r"""
<script>
(function(){
  function showPanel(name){
    document.querySelectorAll("[data-overview-panel]").forEach(function(p){
      p.hidden = p.getAttribute("data-overview-panel")!==name;
    });
    document.querySelectorAll("[data-overview-tab]").forEach(function(b){
      b.setAttribute("aria-selected", b.getAttribute("data-overview-tab")===name ? "true":"false");
    });
  }
  document.querySelectorAll("[data-overview-tab]").forEach(function(btn){
    btn.addEventListener("click", function(){ showPanel(btn.getAttribute("data-overview-tab")); });
  });
  function filterInv(){
    var q=(document.querySelector("[data-inv-search]")||{}).value||"";
    q=String(q).toLowerCase();
    var t=(document.querySelector("[data-inv-filter]")||{}).value||"";
    document.querySelectorAll("[data-inv-row]").forEach(function(tr){
      var name=tr.getAttribute("data-name")||"";
      var typ=tr.getAttribute("data-type")||"";
      var hit=(!q || name.indexOf(q)>=0 || (tr.textContent||"").toLowerCase().indexOf(q)>=0);
      var typOk=!t || typ===t;
      tr.hidden=!(hit && typOk);
    });
  }
  document.querySelectorAll("[data-inv-search]").forEach(function(el){
    el.addEventListener("input", filterInv);
  });
  document.querySelectorAll("[data-inv-filter]").forEach(function(el){
    el.addEventListener("change", filterInv);
  });
  function showTaint(id){
    document.querySelectorAll("[data-taint-panel]").forEach(function(p){
      if(p.getAttribute("data-taint-panel")===id) p.classList.add("is-active");
      else p.classList.remove("is-active");
    });
    var sel=document.querySelector("[data-taint-flow='taint']");
    if(sel && id) sel.value=id;
    var box=document.getElementById("taint-flow-graph");
    if(box && id) box.scrollIntoView({block:"start"});
  }
  document.querySelectorAll("[data-taint-flow='taint']").forEach(function(el){
    el.addEventListener("change", function(){ showTaint(el.value); });
  });
  document.querySelectorAll("[data-graph-filter='taint']").forEach(function(el){
    el.addEventListener("change", function(){
      var taint=document.getElementById("aitrace-taint-data");
      if(!taint) return;
      try{
        var data=JSON.parse(taint.textContent||"{}");
        var cat=el.value;
        var first=(data.flows||[]).filter(function(f){return !cat || f.sink_category===cat;})[0];
        showTaint(first?first.id:"");
      }catch(e){}
    });
  });
  document.querySelectorAll("[data-taint-kind='taint']").forEach(function(el){
    el.addEventListener("change", function(){
      var taint=document.getElementById("aitrace-taint-data");
      if(!taint) return;
      try{
        var data=JSON.parse(taint.textContent||"{}");
        var k=el.value;
        var first=(data.flows||[]).filter(function(f){return !k || f.taint_kind===k;})[0];
        showTaint(first?first.id:"");
      }catch(e){}
    });
  });
  document.querySelectorAll("[data-show-taint-flow]").forEach(function(el){
    el.addEventListener("click", function(){ showTaint(el.getAttribute("data-show-taint-flow")); });
  });
  document.querySelectorAll(".wf-node[data-nid]").forEach(function(g){
    g.addEventListener("click", function(){
      var card=g.closest(".wf-card");
      var detail=card && card.querySelector("[data-wf-detail]");
      if(!detail) return;
      detail.textContent=[
        (g.getAttribute("data-kind")||"component")+": "+((g.querySelector("title")||{}).textContent||g.getAttribute("data-nid")),
        "layer: "+(g.getAttribute("data-layer")||""),
        "invocation_status: "+(g.getAttribute("data-invocation")||"n/a"),
        "taint_status: "+(g.getAttribute("data-taint")||"not_a_sink"),
        "sink_type: "+(g.getAttribute("data-sink")||"none"),
        "source_file: "+(g.getAttribute("data-file")||"unavailable"),
        "source_line: "+(g.getAttribute("data-line")||"—"),
        "callsites: "+(g.getAttribute("data-callsites")||"n/a")
      ].join("\n");
    });
  });
})();
</script>
"""


def _count_exposures(sensitive_exposures: Any) -> int:
    """Count sensitive exposure items from analyzer result."""
    if sensitive_exposures is None:
        return 0
    return len(getattr(sensitive_exposures, "sensitive_exposures", None) or [])


def _count_dataflows(dataflow_analysis: Any, aibom_dataflows: list) -> int:
    """Count the same rows the AI Data Flows table will render."""
    return len(_iter_dataflow_rows(dataflow_analysis, aibom_dataflows))


def to_html_report(
    result: "AnalysisResult",
    out_path: Path,
    exploit_payloads: Optional[List["ExploitPayload"]] = None,
    verification_results: Optional[List["VerificationResult"]] = None,
    generated_at: Optional[str] = None,
    evaluation: Optional[Dict[str, Any]] = None,
    api_inventory: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Build a self-contained HTML report with full scan detail.

    Includes security findings (with PAT-* and taint paths in dropdowns),
    MCP findings, analyzers, policy, architecture Mermaid, optional exploits,
    and optional Langfail evaluation / API inventory tables.
    """
    eval_js = ""
    eval_section = ""
    api_section = ""
    try:
        from core.evaluation.html_sections import (
            EVAL_JS,
            render_api_inventory_section,
            render_evaluation_section,
        )

        eval_js = EVAL_JS
        if evaluation:
            eval_section = render_evaluation_section(evaluation)
        if api_inventory:
            api_section = render_api_inventory_section(api_inventory)
    except ImportError:
        eval_js = ""
    from core.exporters.taint_graph import build_taint_flow_graph

    aibom = result.aibom
    findings = result.findings or []

    repo_name = aibom.repo_path.name
    timestamp = generated_at or datetime.now().strftime("%Y-%m-%d %H:%M")
    repo_type = result.repo_type or "unknown"

    # Security findings only — inventory (dependency discovered, etc.) stays in AI Components
    security_findings = sorted(
        filter_security_findings(findings),
        key=lambda f: _SEV_ORDER.get(f.severity.value.upper(), 99),
    )

    sev_counts: Dict[str, int] = {}
    for f in security_findings:
        k = f.severity.value.upper()
        sev_counts[k] = sev_counts.get(k, 0) + 1

    seen_comp: set = set()
    unique_components = [
        c
        for c in aibom.components
        if not (c.name in seen_comp or seen_comp.add(c.name))  # type: ignore[func-returns-value]
    ]
    n_mcp = len(aibom.mcp_servers)
    n_comp = len(unique_components) + n_mcp
    n_dataflows = _count_dataflows(result.dataflow_analysis, aibom.dataflows)
    n_exposures = _count_exposures(result.sensitive_exposures)

    taint_graph = build_taint_flow_graph(
        result.dataflow_analysis,
        findings,
        result.crossfile_taint,
    )

    verification_map: Dict[str, Any] = {}
    if verification_results:
        verification_map = {r.finding_id: r for r in verification_results}

    parts: List[str] = [
        _head(repo_name),
        "<body>",
        _header(repo_name, timestamp, repo_type),
        _nav(),
        _summary_cards(
            n_comp,
            n_mcp,
            len(security_findings),
            sev_counts,
            n_dataflows,
            n_exposures,
        ),
        _overview_section(
            getattr(result, "architecture_graph", None),
            aibom.components,
            aibom.mcp_servers,
        ),
        eval_section,
        api_section,
        _findings_section(
            security_findings, result.crossfile_taint, taint_graph=taint_graph
        ),
        _sensitive_section(result.sensitive_exposures),
        _prompt_injection_section(result.prompt_injection_risks),
        _taint_graph_section(taint_graph),
        _dataflow_section(result.dataflow_analysis, aibom.dataflows),
        _llm_verification_section(result.llm_verification),
        _policy_section(result.policy_report),
        _exploit_section(exploit_payloads or [], verification_map),
        _downloads_section(out_path),
        _mermaid_script(),
        _GRAPH_JS,
        _OVERVIEW_JS,
        eval_js,
        "</body></html>",
    ]
    return "".join(parts)
