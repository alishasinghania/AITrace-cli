from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional

import typer

from core.cli_support import find_default_policy, resolve_repo_path
from core.engine import AITraceEngine
from core.exporters import (
    to_cyclonedx_json,
    to_risk_report_json,
    to_risk_report_markdown,
    to_spdx_json,
)

app = typer.Typer(help="AITrace - AI Bill of Materials and governance CLI")


class OutputFormat(str, typer.enums.Enum):
    CYCLONEDX = "cyclonedx"
    SPDX = "spdx"
    RISK_JSON = "risk-json"
    RISK_MD = "risk-md"


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
        [OutputFormat.CYCLONEDX, OutputFormat.SPDX, OutputFormat.RISK_JSON],
        "--format",
        "-f",
        help="Output format(s) to generate.",
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

    if OutputFormat.CYCLONEDX in formats:
        cdx = to_cyclonedx_json(result.aibom)
        (out_path / "aitrace-cyclonedx.json").write_text(json.dumps(cdx, indent=2), encoding="utf-8")
        typer.echo("Wrote CycloneDX BOM.")

    if OutputFormat.SPDX in formats:
        spdx = to_spdx_json(result.aibom)
        (out_path / "aitrace-spdx.json").write_text(json.dumps(spdx, indent=2), encoding="utf-8")
        typer.echo("Wrote SPDX document.")

    if OutputFormat.RISK_JSON in formats or OutputFormat.RISK_MD in formats:
        risk_json = to_risk_report_json(result.aibom, result.policy_report)
        (out_path / "aitrace-risk-report.json").write_text(
            json.dumps(risk_json, indent=2),
            encoding="utf-8",
        )
        typer.echo("Wrote Enterprise Risk Report (JSON).")

    if OutputFormat.RISK_MD in formats:
        risk_md = to_risk_report_markdown(result.aibom, result.policy_report)
        (out_path / "aitrace-risk-report.md").write_text(risk_md, encoding="utf-8")
        typer.echo("Wrote Enterprise Risk Report (Markdown).")

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

