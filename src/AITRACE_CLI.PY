from __future__ import annotations

import json
from enum import Enum
from pathlib import Path
from typing import List, Optional

import typer

from core.architecture_inference import infer_architecture
from core.cli_support import find_default_policy, resolve_repo_path
from core.engine import AITraceEngine
from core.exporters import (
    to_ai_component_mermaid,
    to_cyclonedx_json,
    to_findings_json,
    to_risk_report_json,
    to_risk_report_markdown,
    to_spdx_json,
)

app = typer.Typer(help="AITrace - AI Bill of Materials and governance CLI")


class OutputFormat(str, Enum):
    CYCLONEDX = "cyclonedx"
    SPDX = "spdx"
    RISK_JSON = "risk-json"
    RISK_MD = "risk-md"
    MERMAID = "mermaid"


@app.command()
def scan(
    path: Optional[str] = typer.Argument(
        None,
        help="Path to the repository to scan (defaults to current directory).",
    ),
    policy: Optional[str] = typer.Option(
        None,
        "--policy",
        "-p",
        help="Path to policy.yaml. Defaults to ./policy.yaml if present.",
    ),
    out_dir: str = typer.Option(
        "aitrace-out",
        "--out-dir",
        "-o",
        help="Directory where reports will be written.",
    ),
    formats: List[OutputFormat] = typer.Option(
        [
            OutputFormat.CYCLONEDX,
            OutputFormat.SPDX,
            OutputFormat.RISK_JSON,
            OutputFormat.RISK_MD,
            OutputFormat.MERMAID,
        ],
        "--format",
        "-f",
        help="Output format(s) to generate. Pass multiple -f to add; omitting -f uses all formats.",
    ),
) -> None:
    """
    Run AITrace analysis on a repository, optionally applying a policy.yaml and
    generating CycloneDX, SPDX, and Enterprise Risk reports.
    """
    repo_root = resolve_repo_path(path)
    policy_path: Optional[Path]

    if policy is not None:
        policy_path = Path(policy).expanduser().resolve()
    else:
        policy_path = find_default_policy(repo_root)

    typer.echo(f"Analyzing repository at: {repo_root}")
    if policy_path:
        typer.echo(f"Using policy file: {policy_path}")

    engine = AITraceEngine(repo_root)
    result = engine.analyze(policy_path=policy_path)

    out_path = Path(out_dir).expanduser().resolve()
    out_path.mkdir(parents=True, exist_ok=True)

    architecture_result = infer_architecture(result.aibom.repo_path, result.aibom)

    if OutputFormat.CYCLONEDX in formats:
        cdx = to_cyclonedx_json(
            result.aibom,
            architecture_result=architecture_result,
            findings=result.findings,
            llm_usage=result.llm_usage,
            model_supply_chain=result.model_supply_chain,
        )
        (out_path / "aitrace-cyclonedx.json").write_text(json.dumps(cdx, indent=2), encoding="utf-8")
        typer.echo("Wrote CycloneDX BOM.")

    if OutputFormat.SPDX in formats:
        spdx = to_spdx_json(result.aibom, architecture_result)
        (out_path / "aitrace-spdx.json").write_text(json.dumps(spdx, indent=2), encoding="utf-8")
        typer.echo("Wrote SPDX document.")

    if OutputFormat.RISK_JSON in formats or OutputFormat.RISK_MD in formats:
        risk_json = to_risk_report_json(
            result.aibom,
            result.policy_report,
            result.findings,
            architecture_result,
            result.dataflow_analysis,
            result.sensitive_exposures,
            result.model_supply_chain,
            result.prompt_injection_risks,
            result.llm_usage,
            result.repo_type,
        )
        (out_path / "aitrace-risk-report.json").write_text(
            json.dumps(risk_json, indent=2),
            encoding="utf-8",
        )
        typer.echo("Wrote Enterprise Risk Report (JSON).")
        findings_json = to_findings_json(result.findings, architecture_result)
        (out_path / "aitrace-findings.json").write_text(
            json.dumps(findings_json, indent=2),
            encoding="utf-8",
        )
        typer.echo("Wrote findings (JSON).")

    if OutputFormat.RISK_MD in formats:
        risk_md = to_risk_report_markdown(
            result.aibom,
            result.policy_report,
            result.findings,
            architecture_result,
            result.dataflow_analysis,
            result.sensitive_exposures,
            result.model_supply_chain,
            result.prompt_injection_risks,
            result.llm_usage,
            result.repo_type,
        )
        (out_path / "aitrace-risk-report.md").write_text(risk_md, encoding="utf-8")
        typer.echo("Wrote Enterprise Risk Report (Markdown).")

    if OutputFormat.MERMAID in formats:
        mermaid_diagram = to_ai_component_mermaid(result.aibom, architecture_result)
        (out_path / "aitrace-component-diagram.mmd").write_text(mermaid_diagram, encoding="utf-8")
        typer.echo("Wrote AI component diagram (Mermaid).")

    if result.policy_report is not None and not result.policy_report.passed:
        typer.echo("Policy violations detected. Failing build.", err=True)
        raise typer.Exit(code=1)


@app.command("init-policy")
def init_policy(
    path: str = typer.Option(
        "policy.yaml",
        "--path",
        "-p",
        help="Where to write the starter policy.yaml file.",
    ),
) -> None:
    """
    Generate a starter policy.yaml with common fields and comments.
    """
    target = Path(path).expanduser().resolve()
    if target.exists():
        typer.echo(f"Refusing to overwrite existing file: {target}", err=True)
        raise typer.Exit(code=1)

    template = """# AITrace Policy Configuration

licenses:
  # List of SPDX license identifiers that are allowed.
  # If non-empty, any license not listed here will be treated as a violation.
  allowed: []
  # Explicitly denied licenses.
  denied: []
  # If true, any license violation will cause aitrace scan to exit with code 1.
  fail_build: true

models:
  # Approved model names or identifiers.
  approved: []
  # Explicitly denied models.
  denied: []
  fail_build: true

# Model supply chain: trusted/verified orgs for HuggingFace-style model IDs (org/model)
# Models from these orgs are classified as low risk.
model_sources:
  trusted_orgs:
    - google
    - facebook
    - meta
    - microsoft
    - salesforce
    - huggingface
  verified_orgs: []  # Add orgs you have verified (e.g. - mycompany)

risk:
  # Maximum severity allowed before failing the build.
  # One of: info, low, medium, high, critical
  max_severity: high
  fail_build: true
"""
    target.write_text(template, encoding="utf-8")
    typer.echo(f"Wrote starter policy file to {target}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()

