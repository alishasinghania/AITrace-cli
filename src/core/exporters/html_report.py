"""HTML report exporter — generates a single self-contained aitrace-report.html."""

from __future__ import annotations

import html as _html
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from core.engine import AnalysisResult
    from core.features.exploit_synthesizer import ExploitPayload
    from core.features.finding_verifier import VerificationResult
    from core.risk_scoring import RiskScoreResult

_SEV_COLOR: Dict[str, str] = {
    "CRITICAL": "#ef4444",
    "HIGH":     "#f97316",
    "MEDIUM":   "#eab308",
    "LOW":      "#22c55e",
    "INFO":     "#94a3b8",
}
_SEV_ORDER: Dict[str, int] = {
    "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4,
}

_RISK_BAR_COLOR: Dict[str, str] = {
    "High":    "#ef4444",
    "Medium":  "#f97316",
    "Low":     "#eab308",
    "Minimal": "#22c55e",
}


def _e(v: object) -> str:
    return _html.escape(str(v))


def _risk_badge_color(score: int) -> str:
    if score >= 70:
        return "#ef4444"
    if score >= 40:
        return "#f97316"
    return "#22c55e"


_CSS = """
:root{--bg:#0f172a;--card:#1e293b;--border:#334155;--text:#e2e8f0;--muted:#94a3b8;--accent:#818cf8}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:var(--bg);color:var(--text);padding:2rem;max-width:1100px;margin:auto}
a{color:var(--accent);text-decoration:none}
h2{font-size:.8rem;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;margin-bottom:1rem}
.section{margin-bottom:2.5rem}
/* header */
.hdr{display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:1.5rem;margin-bottom:2rem}
.hdr-title{font-size:1.5rem;font-weight:700}
.hdr-sub{font-size:.875rem;color:var(--muted);margin-top:.25rem}
.badge{display:flex;align-items:center;gap:.75rem;padding:.75rem 1.25rem;border-radius:.75rem;font-weight:700}
.badge-score{font-size:2.5rem;line-height:1}
.badge-meta{display:flex;flex-direction:column;gap:.15rem}
.badge-level{font-size:.75rem;font-weight:600;text-transform:uppercase;opacity:.8}
/* metric cards */
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:1rem;margin-bottom:2rem}
.card{background:var(--card);border:1px solid var(--border);border-radius:.75rem;padding:1rem}
.card-val{font-size:1.75rem;font-weight:700;line-height:1}
.card-lbl{font-size:.75rem;color:var(--muted);margin-top:.3rem}
/* severity summary chips */
.sev-row{display:flex;flex-wrap:wrap;gap:.4rem;margin-top:.5rem}
.sev-chip{font-size:.65rem;font-weight:700;padding:.15rem .45rem;border-radius:.25rem;text-transform:uppercase}
/* risk bars */
.bars{display:flex;flex-direction:column;gap:.9rem}
.bar-row{display:grid;grid-template-columns:200px 1fr 48px;align-items:center;gap:1rem}
.bar-name{font-size:.875rem}
.bar-track{height:8px;background:var(--border);border-radius:4px;overflow:hidden}
.bar-fill{height:100%;border-radius:4px}
.bar-sc{font-size:.875rem;color:var(--muted);text-align:right}
/* findings */
.findings{display:flex;flex-direction:column;gap:.75rem}
.finding{background:var(--card);border:1px solid var(--border);border-left:3px solid var(--border);border-radius:.75rem;padding:1rem}
.finding-hdr{display:flex;align-items:flex-start;gap:.75rem}
.sev-badge{font-size:.65rem;font-weight:700;padding:.2rem .55rem;border-radius:.25rem;text-transform:uppercase;flex-shrink:0;margin-top:.15rem;white-space:nowrap}
.finding-title{font-weight:600;font-size:.95rem}
.finding-desc{color:var(--muted);font-size:.85rem;margin-top:.4rem;line-height:1.4}
.finding-loc{font-size:.75rem;font-family:monospace;color:var(--accent);margin-top:.3rem}
/* data flows */
.flows{display:flex;flex-direction:column;gap:.6rem}
.flow{background:var(--card);border:1px solid var(--border);border-radius:.75rem;padding:.875rem 1rem;display:flex;align-items:center;gap:.5rem;flex-wrap:wrap}
.flow-node{background:#1e3a5f;padding:.25rem .6rem;border-radius:.25rem;font-family:monospace;font-size:.8rem}
.flow-arrow{color:var(--muted);font-size:.9rem}
.flow-risk{margin-left:auto;font-size:.7rem;font-weight:700;padding:.15rem .45rem;border-radius:.25rem;text-transform:uppercase}
.flow-sanitized{font-size:.75rem;color:var(--muted);margin-left:.25rem;opacity:.7}
/* mermaid */
.mmd-wrap{background:var(--card);border:1px solid var(--border);border-radius:.75rem;padding:1.5rem;overflow:auto}
.mmd-wrap pre{font-size:.78rem;color:var(--text);white-space:pre;line-height:1.4}
/* downloads */
.dl-row{display:flex;flex-wrap:wrap;gap:.75rem}
.dl-btn{display:inline-block;padding:.5rem 1rem;background:var(--card);border:1px solid var(--accent);border-radius:.5rem;color:var(--accent);font-size:.85rem;text-decoration:none}
.dl-btn:hover{background:var(--accent);color:#fff}
/* empty state */
.empty{color:var(--muted);font-size:.875rem;padding:1rem 0}
/* exploit payloads */
.exploit{background:var(--card);border:1px solid #ef444444;border-left:3px solid #ef4444;border-radius:.75rem;padding:1rem;margin-bottom:.75rem}
.exploit-hdr{display:flex;align-items:flex-start;gap:.75rem;margin-bottom:.5rem}
.exploit-payload{background:#0f172a;border:1px solid var(--border);border-radius:.5rem;padding:.75rem;font-family:monospace;font-size:.78rem;white-space:pre-wrap;color:#a5f3fc;margin-top:.5rem;max-height:160px;overflow-y:auto}
.exploit-meta{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:.4rem;margin-top:.5rem}
.exploit-meta-item{font-size:.75rem;color:var(--muted)}.exploit-meta-item strong{color:var(--text)}
/* verification */
.verdict-confirmed{color:#22c55e}.verdict-likely{color:#f59e0b}.verdict-uncertain{color:#94a3b8}
.verify-ev{font-size:.8rem;padding:.15rem 0;display:flex;gap:.4rem;align-items:flex-start}
/* discovery */
.disc-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:.6rem}
.disc-item{background:var(--card);border:1px solid var(--border);border-radius:.5rem;padding:.65rem .875rem}
"""


def _head(repo_name: str) -> str:
    return (
        "<!DOCTYPE html><html lang='en'><head>"
        "<meta charset='UTF-8'>"
        f"<title>AITrace — {_e(repo_name)}</title>"
        f"<style>{_CSS}</style>"
        "</head>"
    )


def _header(repo_name: str, score: int, level: str, badge_color: str, timestamp: str, repo_type: str) -> str:
    return (
        f"<div class='hdr'>"
        f"<div><div class='hdr-title'>{_e(repo_name)}</div>"
        f"<div class='hdr-sub'>{_e(timestamp)} · {_e(repo_type)} repo</div></div>"
        f"<div class='badge' style='background:{badge_color}18;border:1px solid {badge_color}44'>"
        f"<span class='badge-score' style='color:{badge_color}'>{score}</span>"
        f"<div class='badge-meta'><span class='badge-level' style='color:{badge_color}'>{_e(level)} risk</span>"
        f"<span style='font-size:.75rem;color:var(--muted)'>/ 100 score</span></div>"
        f"</div></div>"
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
    n_models: int,
    n_findings: int,
    n_flows: int,
    sev_counts: Dict[str, int],
) -> str:
    chips = "".join(
        _sev_chip(s, sev_counts.get(s, 0))
        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    )
    return (
        f"<div class='cards'>"
        f"<div class='card'><div class='card-val'>{n_findings}</div>"
        f"<div class='card-lbl'>Findings</div>"
        f"<div class='sev-row'>{chips}</div></div>"
        f"<div class='card'><div class='card-val'>{n_comp}</div><div class='card-lbl'>AI components</div></div>"
        f"<div class='card'><div class='card-val'>{n_models}</div><div class='card-lbl'>Model artifacts</div></div>"
        f"<div class='card'><div class='card-val'>{n_flows}</div><div class='card-lbl'>Data flows</div></div>"
        f"</div>"
    )


def _risk_bars(risk: "RiskScoreResult") -> str:
    bar_color = _RISK_BAR_COLOR.get(risk.risk_level, "#f97316")
    rows = ""
    for dim in risk.dimensions:
        pct = int(100 * dim.score / dim.max_score) if dim.max_score else 0
        rows += (
            f"<div class='bar-row'>"
            f"<span class='bar-name'>{_e(dim.name)}</span>"
            f"<div class='bar-track'><div class='bar-fill' style='width:{pct}%;background:{bar_color}'></div></div>"
            f"<span class='bar-sc'>{dim.score}/{dim.max_score}</span>"
            f"</div>"
        )
    return (
        f"<div class='section'><h2>Risk breakdown</h2>"
        f"<div class='bars'>{rows}</div></div>"
    )


def _findings_section(security_findings: list) -> str:
    """Render only semantic/policy security findings — not component discovery."""
    if not security_findings:
        return (
            "<div class='section'><h2>Security findings</h2>"
            "<div class='empty'>No security findings detected.</div></div>"
        )

    cards = ""
    for f in security_findings:
        sev = f.severity.value.upper()
        color = _SEV_COLOR.get(sev, "#94a3b8")
        loc = ""
        if f.evidence:
            ev = f.evidence[0]
            if ev.file:
                loc_str = ev.file
                if ev.line:
                    loc_str += f":{ev.line}"
                loc = f"<div class='finding-loc'>{_e(loc_str)}</div>"
        cards += (
            f"<div class='finding' style='border-left-color:{color}'>"
            f"<div class='finding-hdr'>"
            f"<span class='sev-badge' style='background:{color}22;color:{color}'>{_e(sev)}</span>"
            f"<span class='finding-title'>{_e(f.title)}</span>"
            f"</div>"
            f"<div class='finding-desc'>{_e(f.description)}</div>"
            f"{loc}"
            f"</div>"
        )
    return (
        f"<div class='section'><h2>Security findings ({len(security_findings)})</h2>"
        f"<div class='findings'>{cards}</div></div>"
    )


_COMP_TYPE_COLOR: Dict[str, str] = {
    "library":        "#6366f1",
    "service":        "#06b6d4",
    "model":          "#a855f7",
    "dataset":        "#f59e0b",
    "infrastructure": "#64748b",
    "application":    "#22c55e",
}


def _components_section(components: list) -> str:
    """Render deduplicated AI components."""
    seen: set = set()
    unique = []
    for c in components:
        if c.name not in seen:
            seen.add(c.name)
            unique.append(c)

    if not unique:
        return ""

    items = ""
    for c in unique:
        ctype = c.type.value.lower()
        color = _COMP_TYPE_COLOR.get(ctype, "#94a3b8")
        ver = f" <span style='color:var(--muted);font-size:.75rem'>{_e(c.version)}</span>" if c.version else ""
        items += (
            f"<div class='card' style='padding:.75rem'>"
            f"<div style='display:flex;align-items:center;gap:.5rem'>"
            f"<span style='font-size:.7rem;font-weight:700;padding:.15rem .4rem;border-radius:.2rem;"
            f"background:{color}22;color:{color};text-transform:uppercase'>{_e(ctype)}</span>"
            f"<span style='font-weight:600;font-size:.875rem'>{_e(c.name)}{ver}</span>"
            f"</div>"
            f"</div>"
        )
    return (
        f"<div class='section'><h2>AI components ({len(unique)})</h2>"
        f"<div class='cards'>{items}</div></div>"
    )


def _dataflows_section(data_flows: list) -> str:
    if not data_flows:
        return ""

    risk_colors = {"high": "#ef4444", "medium": "#f97316", "low": "#eab308"}

    rows = ""
    for flow in data_flows:
        rc = risk_colors.get(flow.risk.lower(), "#94a3b8")
        sanitized_note = "<span class='flow-sanitized'>sanitized</span>" if flow.sanitized else ""
        loc = ""
        if flow.file:
            loc_str = flow.file
            if flow.line:
                loc_str += f":{flow.line}"
            loc = f"<span style='font-size:.75rem;color:var(--muted);font-family:monospace'>{_e(loc_str)}</span>"
        rows += (
            f"<div class='flow'>"
            f"<span class='flow-node'>{_e(flow.source)}</span>"
            f"<span class='flow-arrow'>→</span>"
            f"<span class='flow-node'>{_e(flow.sink)}</span>"
            f"{sanitized_note}"
            f"{loc}"
            f"<span class='flow-risk' style='background:{rc}22;color:{rc}'>{_e(flow.risk)}</span>"
            f"</div>"
        )
    return (
        f"<div class='section'><h2>Data flows ({len(data_flows)})</h2>"
        f"<div class='flows'>{rows}</div></div>"
    )


def _mermaid_section(diagram_src: str) -> str:
    return (
        f"<div class='section'><h2>AI component architecture</h2>"
        f"<div class='mmd-wrap'>"
        f"<div class='mermaid'>{_e(diagram_src)}</div>"
        f"</div></div>"
    )


def _mcp_section(mcp_servers: list) -> str:
    """Render MCP server trust table — highlights suspicious servers."""
    if not mcp_servers:
        return ""

    rows = ""
    for s in mcp_servers:
        trust = s.trust_score
        if trust >= 80:
            trust_color = "#22c55e"
        elif trust >= 50:
            trust_color = "#f59e0b"
        else:
            trust_color = "#ef4444"

        flag = ""
        if s.suspicious_description:
            flag = (
                f"<span style='font-size:.7rem;font-weight:700;color:#ef4444;"
                f"background:#ef444422;padding:.15rem .4rem;border-radius:.2rem;margin-left:.5rem'>"
                f"INJECTION RISK</span>"
            )
            if s.suspicious_tools:
                flag += (
                    f"<div style='font-size:.75rem;color:var(--muted);font-family:monospace;margin-top:.25rem'>"
                    f"suspicious tools: {_e(', '.join(s.suspicious_tools))}</div>"
                )

        rows += (
            f"<div class='finding' style='border-left-color:{trust_color}'>"
            f"<div class='finding-hdr'>"
            f"<span class='sev-badge' style='background:{trust_color}22;color:{trust_color}'>"
            f"trust {trust}</span>"
            f"<span class='finding-title'>{_e(s.name)}</span>"
            f"{flag}"
            f"</div>"
            f"<div class='finding-desc' style='font-family:monospace'>{_e(s.config_path)}"
            + (f" · <span style='color:var(--muted)'>{_e(s.package)}</span>" if s.package else "")
            + f"</div></div>"
        )

    return (
        f"<div class='section'><h2>MCP servers ({len(mcp_servers)})</h2>"
        f"<div class='findings'>{rows}</div></div>"
    )


def _discovery_findings_section(discovery_findings: list) -> str:
    """Render surface/deep discovery findings (dependencies, config, models) as a compact grid."""
    if not discovery_findings:
        return ""

    items = ""
    for f in discovery_findings:
        sev = f.severity.value.upper()
        color = _SEV_COLOR.get(sev, "#94a3b8")
        loc = ""
        if f.evidence:
            ev = f.evidence[0]
            if ev.file:
                loc_str = ev.file + (f":{ev.line}" if ev.line else "")
                loc = f"<div style='font-size:.72rem;font-family:monospace;color:var(--accent);margin-top:.2rem'>{_e(loc_str)}</div>"
        items += (
            f"<div class='disc-item'>"
            f"<div style='display:flex;align-items:center;gap:.5rem'>"
            f"<span class='sev-chip' style='background:{color}22;color:{color}'>{_e(sev)}</span>"
            f"<span style='font-size:.85rem;font-weight:600'>{_e(f.title)}</span>"
            f"</div>{loc}"
            f"</div>"
        )
    return (
        f"<div class='section'><h2>Discovery findings ({len(discovery_findings)})</h2>"
        f"<div class='disc-grid'>{items}</div></div>"
    )


def _exploit_section(
    payloads: List["ExploitPayload"],
    verification_map: Dict[str, "VerificationResult"],
) -> str:
    """Render exploit payloads with static verification results."""
    if not payloads:
        return ""

    _VERDICT_COLORS = {
        "confirmed":  "#22c55e",
        "likely":     "#f59e0b",
        "uncertain":  "#94a3b8",
    }
    _VERDICT_LABELS = {
        "confirmed": "✔ CONFIRMED",
        "likely":    "~ LIKELY",
        "uncertain": "? UNCERTAIN",
    }

    cards = ""
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    for p in sorted(payloads, key=lambda x: sev_order.get(x.severity, 9)):
        sev = p.severity.upper()
        color = _SEV_COLOR.get(sev, "#94a3b8")
        loc = p.target_file + (f":{p.target_line}" if p.target_line else "")

        vr = verification_map.get(p.finding_id)
        verdict_html = ""
        if vr:
            vc = _VERDICT_COLORS.get(vr.verdict, "#94a3b8")
            vl = _VERDICT_LABELS.get(vr.verdict, vr.verdict.upper())
            ev_for_html = "".join(
                f"<div class='verify-ev'><span style='color:#22c55e'>+</span><span>{_e(ev)}</span></div>"
                for ev in vr.evidence_for
            )
            ev_against_html = "".join(
                f"<div class='verify-ev'><span style='color:#ef4444'>−</span><span>{_e(ev)}</span></div>"
                for ev in vr.evidence_against
            )
            verdict_html = (
                f"<div style='margin-top:.6rem;padding:.6rem .75rem;background:#0f172a;"
                f"border-radius:.5rem;border:1px solid {vc}44'>"
                f"<div style='font-size:.8rem;font-weight:700;color:{vc};margin-bottom:.35rem'>"
                f"{_e(vl)} — {vr.confidence}% confidence</div>"
                f"{ev_for_html}{ev_against_html}"
                f"</div>"
            )

        steps_html = "".join(
            f"<li style='font-size:.8rem;color:var(--muted);margin-top:.2rem'>{_e(s)}</li>"
            for s in p.reproduction_steps
        )

        cards += (
            f"<div class='exploit'>"
            f"<div class='exploit-hdr'>"
            f"<span class='sev-badge' style='background:{color}22;color:{color}'>{_e(sev)}</span>"
            f"<div>"
            f"<div style='font-weight:600;font-size:.95rem'>{_e(p.title)}</div>"
            f"<div style='font-size:.75rem;color:var(--muted);font-family:monospace;margin-top:.2rem'>"
            f"{_e(p.finding_id)} · {_e(loc)}</div>"
            f"</div></div>"
            f"<div class='exploit-meta'>"
            f"<div class='exploit-meta-item'><strong>Source:</strong> {_e(p.source_type)}</div>"
            f"<div class='exploit-meta-item'><strong>Sink:</strong> {_e(p.sink_type)}</div>"
            f"<div class='exploit-meta-item'><strong>CVSS:</strong> {_e(p.cvss_vector.split('/')[0] if '/' in p.cvss_vector else p.cvss_vector)}</div>"
            f"</div>"
            f"<div style='font-size:.8rem;color:var(--muted);margin-top:.5rem'>{_e(p.expected_behavior)}</div>"
            f"<div class='exploit-payload'>{_e(p.payload)}</div>"
            f"{verdict_html}"
            f"<details style='margin-top:.6rem'>"
            f"<summary style='font-size:.8rem;color:var(--accent);cursor:pointer'>Reproduction steps</summary>"
            f"<ol style='padding-left:1.2rem;margin-top:.4rem'>{steps_html}</ol>"
            f"</details>"
            f"</div>"
        )

    warning = (
        "<div style='font-size:.8rem;color:#f97316;background:#f9731622;border:1px solid #f9731644;"
        "border-radius:.5rem;padding:.6rem .875rem;margin-bottom:1rem'>"
        "⚠ These payloads are generated for authorized security testing only. "
        "Use only against systems you own or have explicit written permission to test."
        "</div>"
    )
    return (
        f"<div class='section'><h2>Exploit payloads ({len(payloads)})</h2>"
        f"{warning}{cards}</div>"
    )


def _downloads_section() -> str:
    files = [
        ("aitrace-risk-report.md", "Risk Report (Markdown)"),
        ("aitrace-cyclonedx.json", "CycloneDX SBOM"),
        ("aitrace-spdx.json", "SPDX Document"),
        ("aitrace-component-diagram.mmd", "Architecture Diagram"),
    ]
    btns = "".join(
        f"<a class='dl-btn' href='{fn}' download>{_e(label)}</a>"
        for fn, label in files
    )
    return f"<div class='section'><h2>Downloads</h2><div class='dl-row'>{btns}</div></div>"


def _mermaid_script() -> str:
    return (
        "<script type='module'>"
        "import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs';"
        "mermaid.initialize({startOnLoad:true,theme:'dark'});"
        "</script>"
    )


def to_html_report(
    result: "AnalysisResult",
    out_path: Path,
    exploit_payloads: Optional[List["ExploitPayload"]] = None,
    verification_results: Optional[List["VerificationResult"]] = None,
) -> str:
    """Build and return a self-contained HTML report string."""
    from core.risk_scoring import compute_risk_score
    from core.exporters.component_diagram import to_ai_component_mermaid
    from core.models import FindingCategory

    aibom = result.aibom
    findings = result.findings or []
    arch = result.architecture_result

    risk = compute_risk_score(
        aibom,
        findings,
        result.policy_report,
        arch,
        result.sensitive_exposures,
        result.model_supply_chain,
        result.prompt_injection_risks,
        result.dataflow_analysis,
        result.repo_type,
    )

    repo_name = aibom.repo_path.name
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
    badge_color = _risk_badge_color(risk.total_score)

    # Split findings into security (semantic/policy) and discovery (surface/deep)
    security_findings = sorted(
        [f for f in findings if f.category in (FindingCategory.SEMANTIC, FindingCategory.POLICY)],
        key=lambda f: _SEV_ORDER.get(f.severity.value.upper(), 99),
    )
    discovery_findings = sorted(
        [f for f in findings if f.category not in (FindingCategory.SEMANTIC, FindingCategory.POLICY)],
        key=lambda f: _SEV_ORDER.get(f.severity.value.upper(), 99),
    )

    sev_counts: Dict[str, int] = {}
    for f in security_findings:
        k = f.severity.value.upper()
        sev_counts[k] = sev_counts.get(k, 0) + 1

    # Deduplicate components for count display
    seen_comp: set = set()
    unique_components = [c for c in aibom.components if not (c.name in seen_comp or seen_comp.add(c.name))]  # type: ignore[func-returns-value]

    n_comp = len(unique_components)
    n_models = len(aibom.models)
    n_findings = len(security_findings)
    data_flows: list = result.dataflow_analysis.data_flows if result.dataflow_analysis else []
    n_flows = len(data_flows)

    mermaid_src = to_ai_component_mermaid(aibom, arch)

    # Build verification lookup map
    verification_map: Dict[str, Any] = {}
    if verification_results:
        verification_map = {r.finding_id: r for r in verification_results}

    parts: List[str] = [
        _head(repo_name),
        "<body>",
        _header(repo_name, risk.total_score, risk.risk_level, badge_color, timestamp, result.repo_type or "unknown"),
        _summary_cards(n_comp, n_models, n_findings, n_flows, sev_counts),
        _risk_bars(risk),
        _components_section(aibom.components),
        _mcp_section(aibom.mcp_servers),
        _findings_section(security_findings),
        _discovery_findings_section(discovery_findings),
        _dataflows_section(data_flows),
        _exploit_section(exploit_payloads or [], verification_map),
        _mermaid_section(mermaid_src),
        _downloads_section(),
        _mermaid_script(),
        "</body></html>",
    ]
    return "".join(parts)
