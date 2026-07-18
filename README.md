# AITrace — Cross-File Attack Path Analysis and Exploit Synthesis for AI Applications

Traces user-controlled data through AI framework call chains across files and generates working exploit payloads from confirmed attack paths. Static analysis — no running application needed to find the path. Python AI codebases today (LangChain, LangGraph, agents, RAG, MCP).

---

## What it does

- **Traces attack paths** — Follows user input, env vars, and external data through AI framework calls across modules (not single-file grep)
- **Confirms reachability** — Cross-file call-graph analysis marks which paths actually reach LLM, agent, code-exec, or SQL sinks
- **Synthesizes exploits** — With `--exploit`, emits codebase-specific PoC payloads aimed at confirmed sinks, plus static CONFIRMED / LIKELY / UNCERTAIN verdicts
- **Surfaces AI stack context** — Inventories LLM SDKs, agents, RAG, vector stores, and MCP configs so the path has a clear target map
- **One HTML report** — Walk findings and (optional) exploit payloads in the browser after each run

Optional: CycloneDX / SPDX AI BOM and Mermaid diagram via `-f` (not required for the core capability).

---

## Installation

**Requirements:** Python 3.9+ · No telemetry · Core analysis makes no external API calls

```bash
# Recommended
pipx install aitrace-cli
# or
uv tool install aitrace-cli

aitrace --help
```

From source:

```bash
git clone https://github.com/alishasinghania/AITrace-cli
cd AITrace-cli
pip install -e .
```

---

## Usage

```bash
# Analyze a repo — writes aitrace-report.html in the repo root and opens it
aitrace scan ./my-app

# Headless / CI — no browser
aitrace scan ./my-app --no-open

# Generate PoC payloads from confirmed paths (+ RAG poison docs when RAG is present)
aitrace scan ./my-app --exploit

# Optional machine outputs
aitrace scan ./my-app -f cyclonedx -f spdx -f mermaid

# Policy gate (exit code 1 on violation)
aitrace scan ./my-app --policy policy.yaml --no-open

# Write findings JSON + architecture graph
aitrace scan ./my-app --verbose
```

**Live demo (AgentVault):** start the intentionally vulnerable app, run `aitrace scan ./agentvault-demo --exploit`, open the HTML report, copy a CONFIRMED payload, paste it into the running app to show impact. Analysis itself does not require the app to be running.

---

## Demo

<!-- TODO: add assets/demo.gif or demo.mp4 after recording install + analyze + exploit walkthrough -->

```
$ aitrace scan ./agentvault-demo --exploit

Wrote 4 exploit payload(s) to aitrace-exploits.json.

[CRITICAL] Sensitive variable 'DB_PASSWORD' exfiltration via f-string template
  Target: app/agents/primary_agent.py:17   CVSS: 9.3

Static verification:
  ✔ CONFIRMED  [90% confidence]  secret reaches LLM prompt without sanitization

Findings: 18 CRITICAL, 7 HIGH, 2 MEDIUM
Report: ./agentvault-demo/aitrace-report.html
```

Exploit payloads are for **authorized security testing only**.

---

## Output files

By default, artifacts are written into the **scanned repository root**.

| File | When |
|------|------|
| `aitrace-report.html` | Always (primary deliverable) |
| `aitrace-exploits.json` | `--exploit` |
| `aitrace-rag-poison-payload.txt` | `--exploit` + RAG detected |
| `aitrace-cyclonedx.json` | `-f cyclonedx` |
| `aitrace-spdx.json` | `-f spdx` |
| `aitrace-component-diagram.mmd` | `-f mermaid` |
| `aitrace-risk-report.md` | `-f risk-md` |
| `aitrace-findings.json` · arch graph | `--verbose` |

---

## How it works

```
  Discovery          Path analysis              Exploit synthesis
  ─────────          ─────────────              ─────────────────
  manifests          AI call-chain tracing      PoC payloads per
  imports            cross-file confirmation    confirmed sink
  MCP / models       pattern shapes (PAT-*)     static verdicts
         \                |                          /
          \               v                         /
           \----→  HTML report (browser)  ←-------/
```

1. **Discovery** — AI packages, RAG/agent shapes, MCP configs, model artifacts  
2. **Path analysis** — User-controlled data → AI framework sinks across files  
3. **Exploit synthesis** (`--exploit`) — Working payloads + CONFIRMED / LIKELY / UNCERTAIN  
4. **Report** — Single `aitrace-report.html` for walkthroughs and demos  

---

## Policy gate

Optional governance check for CI — not a substitute for path analysis:

```bash
aitrace init-policy
aitrace scan . --policy policy.yaml --no-open
```

Exit code `1` on violation. Example:

```yaml
# GitHub Actions
- name: AITrace policy gate
  run: aitrace scan . --policy policy.yaml --no-open
```

---

## License

MIT.
