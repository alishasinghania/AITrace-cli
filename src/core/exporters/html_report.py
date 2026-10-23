"""HTML report exporter — single self-contained aitrace-report.html with full scan detail."""

from __future__ import annotations

import html as _html
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

from .finding_contract import filter_security_findings

if TYPE_CHECKING:
    from core.engine import AnalysisResult
    from core.features.exploit_synthesizer import ExploitPayload
    from core.features.finding_verifier import VerificationResult

_SEV_COLOR: Dict[str, str] = {
    "CRITICAL": "#ef4444",
    "HIGH": "#f97316",
    "MEDIUM": "#eab308",
    "LOW": "#22c55e",
    "INFO": "#94a3b8",
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


_CSS = """
:root{--bg:#0f172a;--card:#1e293b;--border:#334155;--text:#e2e8f0;--muted:#94a3b8;--accent:#818cf8}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:var(--bg);color:var(--text);padding:2rem;max-width:1100px;margin:auto}
a{color:var(--accent);text-decoration:none}
h2{font-size:.8rem;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;margin-bottom:1rem}
h3{font-size:.75rem;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:.75rem;margin-top:1.5rem}
.section{margin-bottom:2.5rem}
.hdr{margin-bottom:2rem}
.hdr-title{font-size:1.5rem;font-weight:700}
.hdr-sub{font-size:.875rem;color:var(--muted);margin-top:.25rem}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:1rem;margin-bottom:2rem}
.card{background:var(--card);border:1px solid var(--border);border-radius:.75rem;padding:1rem}
.card-val{font-size:1.75rem;font-weight:700;line-height:1}
.card-lbl{font-size:.75rem;color:var(--muted);margin-top:.3rem}
.sev-row{display:flex;flex-wrap:wrap;gap:.4rem;margin-top:.5rem}
.sev-chip{font-size:.65rem;font-weight:700;padding:.15rem .45rem;border-radius:.25rem;text-transform:uppercase}
.comp-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:.6rem}
.comp-card{background:var(--card);border:1px solid var(--border);border-radius:.5rem;padding:.65rem .875rem;min-width:0;overflow:hidden}
.comp-name{font-weight:600;font-size:.875rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.comp-ver{color:var(--muted);font-size:.75rem}
.mcp-list{display:flex;flex-direction:column;gap:.6rem}
.mcp-row{background:var(--card);border:1px solid var(--border);border-radius:.5rem;padding:.75rem 1rem}
.mcp-head{display:flex;align-items:center;gap:.75rem;flex-wrap:wrap}
.mcp-name{font-weight:600;font-size:.9rem}
.mcp-meta{font-size:.75rem;font-family:monospace;color:var(--muted);margin-left:auto;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:320px}
.inj-badge{font-size:.65rem;font-weight:700;padding:.2rem .5rem;border-radius:.25rem;background:#ef444422;color:#ef4444;flex-shrink:0}
.mcp-findings{margin-top:.5rem;padding-left:1rem;font-size:.78rem;color:var(--muted);line-height:1.4}
.src-badge{font-size:.62rem;font-weight:700;padding:.15rem .4rem;border-radius:.25rem;background:#ffffff11;color:var(--muted);text-transform:lowercase;flex-shrink:0;margin-top:.15rem;white-space:nowrap}
details.finding{background:var(--card);border:1px solid var(--border);border-left:3px solid var(--border);border-radius:.75rem;overflow:hidden;margin-bottom:.5rem}
details.finding summary{list-style:none;padding:.875rem 1rem;cursor:pointer;display:flex;align-items:flex-start;gap:.6rem;user-select:none}
details.finding summary::-webkit-details-marker{display:none}
details.finding[open]>summary{border-bottom:1px solid var(--border)}
.f-chevron{flex-shrink:0;margin-top:.2rem;color:var(--muted);transition:transform .15s}
details.finding[open] .f-chevron{transform:rotate(90deg)}
.f-body{padding:.875rem 1rem;display:flex;flex-direction:column;gap:.4rem}
.sev-badge{font-size:.65rem;font-weight:700;padding:.2rem .55rem;border-radius:.25rem;text-transform:uppercase;flex-shrink:0;margin-top:.1rem;white-space:nowrap}
.finding-title{font-weight:600;font-size:.95rem;flex:1}
.finding-desc{color:var(--muted);font-size:.85rem;line-height:1.4}
.finding-loc{font-size:.75rem;font-family:monospace;color:var(--accent)}
.finding-count{font-size:.7rem;font-weight:700;padding:.15rem .45rem;border-radius:.25rem;background:#ffffff11;color:var(--muted);flex-shrink:0;margin-top:.15rem}
.sub-finding{border-top:1px solid var(--border);padding-top:.6rem;margin-top:.2rem}
.sub-finding:first-child{border-top:none;padding-top:0;margin-top:0}
.table-wrap{overflow:auto;border:1px solid var(--border);border-radius:.75rem}
table{width:100%;border-collapse:collapse;font-size:.8rem}
th,td{padding:.6rem .75rem;border-bottom:1px solid var(--border);text-align:left;vertical-align:top}
th{color:var(--muted);font-size:.7rem;text-transform:uppercase;letter-spacing:.04em;background:#0a0f1e}
tr:last-child td{border-bottom:none}
.path-card{background:var(--card);border:1px solid var(--border);border-radius:.5rem;padding:.75rem 1rem;margin-bottom:.5rem;font-size:.85rem}
.path-chain{font-family:monospace;color:var(--accent);margin-top:.35rem;line-height:1.4;word-break:break-word}
.mmd-wrap{background:var(--card);border:1px solid var(--border);border-radius:.75rem;padding:1.5rem;overflow:auto}
.dl-row{display:flex;flex-wrap:wrap;gap:.75rem}
.dl-btn{display:inline-block;padding:.5rem 1rem;background:var(--card);border:1px solid var(--accent);border-radius:.5rem;color:var(--accent);font-size:.85rem;text-decoration:none}
.dl-btn:hover{background:var(--accent);color:#fff}
.empty{color:var(--muted);font-size:.875rem;padding:1rem 0}
.eval-meta{width:100%;margin:.75rem 0 1rem;font-size:.8rem}
.eval-meta th{width:8rem}
button[data-eval-filter]{margin-right:.35rem;margin-bottom:.35rem;padding:.2rem .5rem;background:var(--card);border:1px solid var(--border);color:var(--text);border-radius:.35rem;cursor:pointer;font-size:.75rem}
.policy-pass{color:#22c55e}.policy-fail{color:#ef4444}
details.exploit-card{background:var(--card);border:1px solid #ef444433;border-left:3px solid #ef4444;border-radius:.75rem;overflow:hidden;margin-bottom:.5rem}
details.exploit-card summary{list-style:none;padding:.875rem 1rem;cursor:pointer;display:flex;align-items:flex-start;gap:.6rem;user-select:none}
details.exploit-card summary::-webkit-details-marker{display:none}
details.exploit-card[open]>summary{border-bottom:1px solid var(--border)}
details.exploit-card[open] .f-chevron{transform:rotate(90deg)}
.exploit-body{padding:1rem;display:flex;flex-direction:column;gap:.75rem}
.exploit-meta{display:flex;flex-wrap:wrap;gap:.5rem}
.exploit-meta-pill{font-size:.72rem;padding:.2rem .6rem;border-radius:.25rem;background:#ffffff08;color:var(--muted)}
.exploit-meta-pill strong{color:var(--text);font-weight:600}
.exploit-desc{font-size:.85rem;color:var(--muted);line-height:1.5}
.payload-block{background:#0a0f1e;border:1px solid var(--border);border-radius:.5rem;overflow:auto;max-height:220px;font-family:'SF Mono',ui-monospace,monospace;font-size:.76rem;line-height:1.6}
.pl{display:flex}
.pl:hover{background:#ffffff08}
.ln{min-width:2.6rem;text-align:right;padding:0 .75rem;color:#3d5068;user-select:none;flex-shrink:0;border-right:1px solid #1e2d3d}
.lc{color:#a5f3fc;white-space:pre;padding:0 .75rem}
.verdict-box{border-radius:.5rem;padding:.6rem .75rem;background:#0a0f1e}
.verify-ev{font-size:.8rem;padding:.15rem 0;display:flex;gap:.4rem;align-items:flex-start}
details.exploit-gate{margin-bottom:2.5rem}
details.exploit-gate>summary{list-style:none;cursor:pointer;display:flex;align-items:center;gap:.75rem;padding:1rem 1.25rem;background:#1a0a0a;border:1px solid #7f1d1d;border-radius:.75rem;user-select:none}
details.exploit-gate>summary::-webkit-details-marker{display:none}
details.exploit-gate[open]>summary{border-radius:.75rem .75rem 0 0;border-bottom-color:#431407}
.gate-lock{font-size:1.1rem;flex-shrink:0}
.gate-title{font-size:.85rem;font-weight:700;color:#fca5a5;flex:1}
.gate-subtitle{font-size:.75rem;color:#f87171;opacity:.8}
.gate-chevron{flex-shrink:0;color:#f87171;transition:transform .15s}
details.exploit-gate[open] .gate-chevron{transform:rotate(90deg)}
.gate-body{background:#130808;border:1px solid #7f1d1d;border-top:none;border-radius:0 0 .75rem .75rem;padding:1.25rem}
.gate-warning{font-size:.8rem;color:#f97316;background:#f9731611;border:1px solid #f9731633;border-radius:.5rem;padding:.6rem .875rem;margin-bottom:.75rem}
.graph-shell{background:var(--card);border:1px solid var(--border);border-radius:.75rem;overflow:hidden;margin-bottom:.75rem}
.graph-toolbar{display:flex;flex-wrap:wrap;gap:.5rem;align-items:center;padding:.65rem .75rem;border-bottom:1px solid var(--border)}
.graph-toolbar input,.graph-toolbar select{background:#0a0f1e;border:1px solid var(--border);color:var(--text);border-radius:.4rem;padding:.3rem .5rem;font-size:.8rem}
.graph-toolbar button{background:#0a0f1e;border:1px solid var(--accent);color:var(--accent);border-radius:.4rem;padding:.3rem .6rem;font-size:.75rem;cursor:pointer}
.graph-canvas{width:100%;height:420px;background:#0a0f1e;touch-action:none}
.graph-detail{padding:.75rem 1rem;font-size:.8rem;color:var(--muted);min-height:3rem;border-top:1px solid var(--border);white-space:pre-wrap}
.graph-fallback{font-size:.8rem;margin-top:.5rem}
.graph-fallback li{margin:.25rem 0;color:var(--muted)}
.graph-legend{display:flex;flex-wrap:wrap;gap:.5rem;margin:.5rem 0;font-size:.7rem;color:var(--muted)}
.graph-legend span{display:inline-flex;align-items:center;gap:.3rem}
.graph-swatch{width:.65rem;height:.65rem;border-radius:50%;display:inline-block}
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
        f"<div class='cards'>"
        f"<div class='card'><div class='card-val'>{n_findings}</div>"
        f"<div class='card-lbl'>Security findings</div>"
        f"<div class='sev-row'>{finding_chips}</div></div>"
        f"<div class='card'><div class='card-val'>{n_comp}</div>"
        f"<div class='card-lbl'>AI components</div>"
        f"<div class='sev-row'>"
        f"<span class='sev-chip' style='background:#6366f122;color:#6366f1'>{lib_count} libraries</span>"
        f"<span class='sev-chip' style='background:#0ea5e922;color:#0ea5e9'>{n_mcp} MCP</span>"
        f"</div></div>"
        f"<div class='card'><div class='card-val'>{n_dataflows}</div>"
        f"<div class='card-lbl'>Data flows</div></div>"
        f"<div class='card'><div class='card-val'>{n_exposures}</div>"
        f"<div class='card-lbl'>Sensitive exposures</div></div>"
        f"</div>"
    )


def _ai_components_section(components: list, mcp_servers: list) -> str:
    """Libraries grid plus MCP rows with security findings (no trust score)."""
    seen: set = set()
    libraries = []
    for c in components:
        if c.name not in seen:
            seen.add(c.name)
            libraries.append(c)

    if not libraries and not mcp_servers:
        return ""

    lib_items = ""
    for c in libraries:
        ver = f"<div class='comp-ver'>{_e(c.version)}</div>" if c.version else ""
        lib_items += (
            f"<div class='comp-card'>"
            f"<div class='comp-name'>{_e(c.name)}</div>"
            f"{ver}</div>"
        )

    mcp_rows = ""
    for s in mcp_servers:
        has_injection = bool(getattr(s, "suspicious_description", False))
        has_findings = bool(getattr(s, "security_findings", None))
        border = "#ef4444" if (has_injection or has_findings) else "var(--border)"

        inj_badge = ""
        if has_injection:
            inj_badge = "<span class='inj-badge'>INJECTION RISK</span>"

        meta = _e(s.config_path)
        if s.package:
            meta += f" · {_e(s.package)}"

        findings_html = ""
        sec = getattr(s, "security_findings", None) or []
        if sec:
            items = "".join(f"<li>{_e(x)}</li>" for x in sec[:8])
            findings_html = f"<ul class='mcp-findings'>{items}</ul>"

        mcp_rows += (
            f"<div class='mcp-row' style='border-left:3px solid {border}'>"
            f"<div class='mcp-head'>"
            f"<span class='mcp-name'>{_e(s.name)}</span>"
            f"{inj_badge}"
            f"<span class='mcp-meta'>{meta}</span>"
            f"</div>{findings_html}</div>"
        )

    total = len(libraries) + len(mcp_servers)
    lib_section = (
        f"<h3>Libraries</h3><div class='comp-grid'>{lib_items}</div>" if lib_items else ""
    )
    mcp_section = (
        f"<h3>MCP Servers</h3><div class='mcp-list'>{mcp_rows}</div>" if mcp_rows else ""
    )
    return (
        f"<div class='section'><h2>AI Components ({total})</h2>"
        f"{lib_section}{mcp_section}</div>"
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
        # Keep paths short for demos: first → … → last
        if len(hops) <= 3:
            chain = " → ".join(hops)
        else:
            chain = f"{hops[0]} → … → {hops[-1]}"
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


def _finding_detail_html(
    finding: Any,
    taint_by_pat: Dict[str, List[str]],
    *,
    show_instance_label: bool = False,
    group_key: str = "",
) -> str:
    """Short, plain-language dropdown body for demos and leadership reviews."""
    meta = getattr(finding, "metadata", None) or {}
    fid = str(getattr(finding, "id", "") or "")
    parts: List[str] = []

    if show_instance_label and group_key:
        label = _instance_label(finding, group_key)
        parts.append(f"<strong>{_e(label)}</strong>")

    # What / Where / Why / Fix — keep it scannable
    parts.append(
        f"<div class='finding-desc'><strong>What we found:</strong> {_e(_plain_title(finding))}</div>"
    )

    loc = _finding_loc_str(finding)
    if loc:
        parts.append(
            f"<div class='finding-loc'><strong>Where:</strong> {_e(loc)}</div>"
        )

    parts.append(
        f"<div class='finding-desc'><strong>Why it matters:</strong> {_e(_why_it_matters(finding))}</div>"
    )

    paths = taint_by_pat.get(fid, [])[:2]
    if paths or meta.get("confirmed_by_taint"):
        if paths:
            parts.append(
                "<div class='hdr-sub' style='margin-top:.35rem'>How the attack reaches the AI</div>"
            )
            for p in paths:
                parts.append(f"<div class='path-chain'>{_e(p)}</div>")
        else:
            parts.append(
                "<div class='hdr-sub' style='margin-top:.35rem'>"
                "Confirmed: untrusted data can reach the AI across files</div>"
            )

    rem = meta.get("remediation")
    if rem:
        # First sentence only — avoid long technical paragraphs in demos
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
) -> str:
    """
    Render security findings as grouped collapsible details.

    Pattern (PAT-*) and taint-confirmed findings are included here with path
    details in the dropdown — no separate Pattern/Taint sections.
    """
    if not security_findings:
        return (
            "<div class='section'><h2>Security Findings</h2>"
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
            body_inner = _finding_detail_html(group[0], taint_by_pat)
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
    return f"<div class='section'><h2>{heading}</h2>{cards}</div>"


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


def _dataflow_trace(df: Any) -> str:
    """Ordered hops from the taint DataFlow only — never architecture graphs."""
    hops = [str(h).strip() for h in (getattr(df, "hops", None) or []) if str(h).strip()]
    if not hops:
        return "—"
    return " → ".join(hops)


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
        f"<div class='path-chain'>{_e(_dataflow_trace(df))}</div>",
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
    """Dataflow summary from analyzer taint flows only, plus a hop graph."""
    from core.exporters.taint_diagram import taint_mermaid_for_analysis

    flows = _iter_dataflow_rows(dataflow_analysis, aibom_dataflows)
    notice = _dataflow_incomplete_notice(dataflow_analysis) + _dataflow_coverage_notice(
        dataflow_analysis
    )
    if not flows and not notice:
        return ""

    graph = ""
    mermaid_src = taint_mermaid_for_analysis(dataflow_analysis)
    if mermaid_src:
        graph = (
            "<div class='hdr-sub' style='margin-bottom:.75rem'>"
            "Value-taint movement: HTTP/source functions (red) through callees "
            "(blue) into sinks (orange). This is not the AIBOM architecture graph."
            "</div>"
            f"<div class='mmd-wrap'><div class='mermaid'>{_e(mermaid_src)}</div></div>"
        )

    rows = [r for r in (_dataflow_table_row(df) for df in flows[:40]) if r]
    table = _analyzer_table_section(
        "AI Data Flows",
        rows,
        ["Risk", "Source", "Sink", "Category", "Location", "Trace", "Notes"],
    ) if rows else ""
    # Keep a single h2 when we prepend the graph above the existing table section.
    if table and graph:
        marker = f"<h2>AI Data Flows ({len(rows)})</h2>"
        if marker in table:
            table = table.replace(marker, marker + graph, 1)
            graph = ""
    if notice and not table:
        return (
            f"<div class='section'><h2>AI Data Flows</h2>{notice}{graph}</div>"
        )
    body = f"{notice}{graph}{table}"
    return body


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
    """Optional LLM verification results."""
    if llm_verification is None:
        return ""
    verifications = getattr(llm_verification, "verifications", []) or []
    if not verifications:
        return ""

    verified = [v for v in verifications if getattr(v, "verified", False) and not getattr(v, "false_positive", False)]
    dismissed = [v for v in verifications if getattr(v, "false_positive", False)]
    cards = ""
    for v in verified:
        cards += (
            f"<div class='path-card'>"
            f"<strong>{_e(v.finding_id)}</strong> VERIFIED "
            f"({_e(getattr(v, 'cvss_estimate', '?'))}/10) "
            f"<div class='finding-desc'>{_e(getattr(v, 'attack_scenario', ''))}</div>"
            f"</div>"
        )
    for v in dismissed:
        cards += (
            f"<div class='path-card'>"
            f"<strong>{_e(v.finding_id)}</strong> FALSE POSITIVE — "
            f"{_e(getattr(v, 'false_positive_reason', ''))}</div>"
        )
    summary = (
        f"{getattr(llm_verification, 'findings_verified', 0)} verified · "
        f"{getattr(llm_verification, 'findings_dismissed', 0)} dismissed · "
        f"{getattr(llm_verification, 'api_calls_made', 0)} API calls"
    )
    return (
        f"<div class='section'><h2>LLM Verification</h2>"
        f"<div class='hdr-sub' style='margin-bottom:.75rem'>{_e(summary)}</div>"
        f"{cards}</div>"
    )


def _mermaid_section(diagram_src: str, extra_diagrams: Optional[List[Tuple[str, str]]] = None) -> str:
    """Render architecture Mermaid, plus optional labeled extra diagrams."""
    parts = [
        "<div class='section'><h2>AI component architecture</h2>",
        "<div class='hdr-sub' style='margin-bottom:.75rem'>"
        "Packages, in-repo HTTP handlers, agents, LLM backends, and SQL/exec "
        "sites. Dashed edges are structural uses — value-taint movement is in "
        "AI Data Flows."
        "</div>",
        f"<div class='mmd-wrap'><div class='mermaid'>{_e(diagram_src)}</div></div>",
    ]
    for title, src in extra_diagrams or []:
        if not src:
            continue
        parts.append(f"<h3>{_e(title)}</h3>")
        parts.append(
            "<div class='hdr-sub' style='margin-bottom:.5rem'>"
            "AIBOM semantic flow pattern (not a confirmed value-taint path)."
            "</div>"
        )
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
    return f"<div class='section'><h2>Downloads</h2><div class='dl-row'>{btns}</div></div>"


def _mermaid_script() -> str:
    return (
        "<script type='module'>"
        "import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs';"
        "mermaid.initialize({startOnLoad:true,theme:'dark'});"
        "</script>"
    )


_GRAPH_KIND_COLORS = {
    "api_endpoint": "#f59e0b",
    "agent": "#a78bfa",
    "prompt_builder": "#22d3ee",
    "llm_provider": "#60a5fa",
    "embedding_model": "#4ade80",
    "vector_db": "#34d399",
    "retriever": "#2dd4bf",
    "memory": "#c084fc",
    "tool": "#fb7185",
    "mcp_server": "#fb923c",
    "database": "#67e8f9",
    "http_client": "#94a3b8",
    "security_control": "#86efac",
    "function": "#64748b",
    "source": "#ef4444",
    "sink": "#f97316",
    "intermediate": "#3b82f6",
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
        items.append(
            f"<li>edge {_e(e.get('relationship') or e.get('label') or 'rel')} "
            f"{_e(e.get('source'))} → {_e(e.get('target'))} "
            f"[{_e(e.get('evidence_status'))}]</li>"
        )
    return f"<ul class='graph-fallback'>{''.join(items)}</ul>"


def _legend_html(kinds: List[str]) -> str:
    chips = []
    for k in kinds:
        color = _GRAPH_KIND_COLORS.get(k, "#94a3b8")
        chips.append(
            f"<span><i class='graph-swatch' style='background:{color}'></i>{_e(k)}</span>"
        )
    return f"<div class='graph-legend'>{''.join(chips)}</div>"


def _architecture_graph_section(graph: Optional[Dict[str, Any]]) -> str:
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
    return (
        "<div class='section' id='architecture-graph'>"
        "<h2>AI application architecture</h2>"
        "<div class='hdr-sub'>Observed components and calls from source and MCP config. "
        f"{n_n} nodes · {n_e} edges. This is not a taint graph.</div>"
        + _legend_html(kinds)
        + body
        + _graph_fallback_list(graph)
        + _json_script("aitrace-arch-data", graph)
        + "</div>"
    )


def _taint_graph_section(graph: Optional[Dict[str, Any]]) -> str:
    """Interactive taint-flow graph plus a text fallback."""
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
    body = (
        "<div class='empty'>No confirmed value-taint flows were recorded.</div>"
        if empty
        else (
            "<div class='graph-shell'>"
            "<div class='graph-toolbar'>"
            "<select data-taint-flow='taint' aria-label='Select taint flow'>"
            "<option value=''>All flows</option>"
            + "".join(
                f"<option value='{_e(f.get('id'))}'>"
                f"{_e(f.get('sink_category') or 'flow')} "
                f"{_e(f.get('sink_file') or '')}:{_e(f.get('sink_line') or '—')}"
                "</option>"
                for f in graph.get("flows") or []
            )
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
            "<svg class='graph-canvas' id='aitrace-taint-svg' role='img' "
            "aria-label='Taint-flow graph'></svg>"
            "<div class='graph-detail' id='aitrace-taint-detail'>Select a flow for source, sink, and hops.</div>"
            "</div>"
        )
    )
    return (
        "<div class='section' id='taint-flow-graph'>"
        "<h2>Taint-flow graph</h2>"
        "<div class='hdr-sub'>Confirmed value-taint DataFlows only. "
        f"{n_f} flows · {n_s} unique sinks. Architecture edges are not included.</div>"
        + body
        + _graph_fallback_list(graph, taint=True)
        + struct_html
        + _json_script("aitrace-taint-data", graph)
        + "</div>"
    )


_GRAPH_JS = r"""
<script>
(function(){
  function parse(id){
    var el=document.getElementById(id);
    if(!el) return null;
    try{return JSON.parse(el.textContent||"{}");}catch(e){return null;}
  }
  function layout(nodes, kinds){
    var cols={};
    kinds.forEach(function(k,i){cols[k]=i;});
    var colCount=Math.max(kinds.length,1);
    var buckets={};
    nodes.forEach(function(n){
      var k=n.kind||n.role||"other";
      (buckets[k]=buckets[k]||[]).push(n);
    });
    var W=1100,H=400,left=70,top=40;
    var pos={};
    Object.keys(buckets).forEach(function(k){
      var col=cols[k]!=null?cols[k]:colCount-1;
      var list=buckets[k];
      list.forEach(function(n,i){
        pos[n.id]={
          x:left+col*((W-140)/Math.max(colCount-1,1)),
          y:top+i*((H-80)/Math.max(list.length-1,1)),
          n:n
        };
      });
    });
    return pos;
  }
  function colors(){return {
    api_endpoint:"#f59e0b",agent:"#a78bfa",prompt_builder:"#22d3ee",llm_provider:"#60a5fa",
    embedding_model:"#4ade80",vector_db:"#34d399",retriever:"#2dd4bf",memory:"#c084fc",
    tool:"#fb7185",mcp_server:"#fb923c",database:"#67e8f9",http_client:"#94a3b8",
    security_control:"#86efac",function:"#64748b",source:"#ef4444",sink:"#f97316",
    intermediate:"#3b82f6",other:"#94a3b8"
  };}
  function render(svg, data, opts){
    if(!svg||!data) return;
    var nodes=(data.nodes||[]).slice(0,80);
    var edges=(data.edges||[]).slice(0,160);
    var kinds=[];
    nodes.forEach(function(n){
      var k=n.kind||n.role||"other";
      if(kinds.indexOf(k)<0) kinds.push(k);
    });
    var pos=layout(nodes, kinds);
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
        parts.push("<line x1='"+a.x+"' y1='"+a.y+"' x2='"+b.x+"' y2='"+b.y+
          "' stroke='"+(hot?"#c4b5fd":"#334155")+"' stroke-width='"+(hot?2.4:1.2)+"'/>");
      });
      visN.forEach(function(n){
        var p=pos[n.id]; if(!p) return;
        var k=n.kind||n.role||"other";
        var hot=selected===n.id || (flowFilter && (n.id));
        parts.push("<g data-nid='"+n.id.replace(/"/g,"")+"' style='cursor:pointer'>");
        parts.push("<circle cx='"+p.x+"' cy='"+p.y+"' r='"+(hot?14:11)+"' fill='"+(C[k]||C.other)+"' stroke='#0f172a' stroke-width='2'/>");
        parts.push("<text x='"+(p.x+16)+"' y='"+(p.y+4)+"' fill='#e2e8f0' font-size='11'>"+
          (n.label||n.id).replace(/[<>]/g,"")+"</text></g>");
      });
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
              "status: "+(n.evidence_status||n.confidence||"")
            ].join("\n");
          }
          draw();
        });
      });
    }
    svg.addEventListener("wheel", function(e){
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
    draw();
    return {
      setFilter: function(v){filter=v||"";draw();},
      setSearch: function(v){search=(v||"").toLowerCase();draw();},
      setFlow: function(v){flowFilter=v||"";selected=v||null;
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
      reset: function(){vx=0;vy=0;scale=1;selected=null;filter="";search="";flowFilter="";draw();}
    };
  }
  var arch=parse("aitrace-arch-data");
  var taint=parse("aitrace-taint-data");
  var archCtl=render(document.getElementById("aitrace-arch-svg"), arch, {detail:document.getElementById("aitrace-arch-detail")});
  var taintCtl=render(document.getElementById("aitrace-taint-svg"), taint, {detail:document.getElementById("aitrace-taint-detail")});
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
    from core.evaluation.html_sections import (
        EVAL_JS,
        render_api_inventory_section,
        render_evaluation_section,
    )
    from core.exporters.component_diagram import to_ai_component_mermaid
    from core.exporters.taint_graph import build_taint_flow_graph

    aibom = result.aibom
    findings = result.findings or []
    arch = result.architecture_result

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

    mermaid_src = to_ai_component_mermaid(
        aibom, arch, dataflow_analysis=result.dataflow_analysis
    )
    extra_arch: List[Tuple[str, str]] = []
    for dg in aibom.dataflows or []:
        title = getattr(dg, "flow_type", None) or "AI flow pattern"
        extra_arch.append((str(title), dg.to_mermaid(layout="LR")))

    verification_map: Dict[str, Any] = {}
    if verification_results:
        verification_map = {r.finding_id: r for r in verification_results}

    parts: List[str] = [
        _head(repo_name),
        "<body>",
        _header(repo_name, timestamp, repo_type),
        _summary_cards(
            n_comp,
            n_mcp,
            len(security_findings),
            sev_counts,
            n_dataflows,
            n_exposures,
        ),
        _ai_components_section(aibom.components, aibom.mcp_servers),
        render_evaluation_section(evaluation) if evaluation else "",
        render_api_inventory_section(api_inventory) if api_inventory else "",
        _architecture_graph_section(getattr(result, "architecture_graph", None)),
        _findings_section(security_findings, result.crossfile_taint),
        _sensitive_section(result.sensitive_exposures),
        _prompt_injection_section(result.prompt_injection_risks),
        _taint_graph_section(
            build_taint_flow_graph(
                result.dataflow_analysis,
                findings,
                result.crossfile_taint,
            )
        ),
        _dataflow_section(result.dataflow_analysis, aibom.dataflows),
        _llm_verification_section(result.llm_verification),
        _policy_section(result.policy_report),
        _exploit_section(exploit_payloads or [], verification_map),
        _mermaid_section(mermaid_src, extra_arch),
        _downloads_section(out_path),
        _mermaid_script(),
        _GRAPH_JS,
        EVAL_JS,
        "</body></html>",
    ]
    return "".join(parts)
