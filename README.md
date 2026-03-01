## AITrace CLI (Prototype)

AITrace is an enterprise-grade CLI for generating AI Bills of Materials (AIBOM)
and performing deep architectural discovery of AI components in repositories.

This prototype implements:

- Surface discovery of dependencies and cloud providers.
- Deep inspection of model artefacts and configurations.
- Semantic mapping of AI inference calls and Mermaid.js diagrams.
- A `policy.yaml` engine for governance.
- Export of CycloneDX 1.7 (JSON subset), SPDX 3.0 (JSON subset), and a custom
  Enterprise Risk Report (JSON + Markdown).

### Quick start

1. Install dependencies:

```bash
pip install -r requirements.txt
```

2. Initialize a policy file (optional but recommended):

```bash
python -m AITRACE_CLI init-policy
```

3. Run a scan:

```bash
python -m AITRACE_CLI scan . --out-dir aitrace-out
```

This will generate:

- `aitrace-out/aitrace-cyclonedx.json`
- `aitrace-out/aitrace-spdx.json`
- `aitrace-out/aitrace-risk-report.json`
- `aitrace-out/aitrace-risk-report.md` (when `--format risk-md` is used)

