from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import webbrowser
from enum import Enum
from pathlib import Path
from typing import Any, List, Optional, Tuple

import typer

from core.governance.cli_support import find_default_policy, resolve_repo_path
from core.engine import AITraceEngine
from core.exporters import (
    to_ai_component_mermaid,
    to_cyclonedx_json,
    to_findings_json,
    to_risk_report_json,
    to_risk_report_markdown,
    to_spdx_json,
)

app = typer.Typer(help="AITrace - Attack path analysis and exploit synthesis for AI applications.")


def _clone_if_url(path: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """
    If path looks like a remote git URL, clone it to a temp directory.

    Returns (local_path, tmp_dir_to_cleanup).
    tmp_dir_to_cleanup is None when no cloning was done (caller must delete it).
    Supports:
      https://github.com/owner/repo
      https://github.com/owner/repo.git
      git@github.com:owner/repo.git
      Any https:// or git@ URL
    """
    if path is None:
        return path, None
    if not (
        path.startswith("https://")
        or path.startswith("http://")
        or path.startswith("git@")
        or (path.startswith("git://"))
    ):
        return path, None

    tmp_dir = tempfile.mkdtemp(prefix="aitrace-clone-")
    typer.echo(f"Cloning {path} …")
    try:
        result = subprocess.run(
            ["git", "clone", "--depth=1", path, tmp_dir],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            typer.echo(f"Error: git clone failed:\n{result.stderr.strip()}", err=True)
            raise typer.Exit(code=1)
    except FileNotFoundError:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        typer.echo("Error: git is not installed or not on PATH.", err=True)
        raise typer.Exit(code=1)

    typer.echo(f"Cloned to {tmp_dir}")
    return tmp_dir, tmp_dir


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
        help="Local path or remote GitHub URL to scan (defaults to current directory).",
    ),
    policy: Optional[str] = typer.Option(
        None,
        "--policy",
        "-p",
        help="Path to policy.yaml. Defaults to ./policy.yaml if present.",
    ),
    out_dir: Optional[str] = typer.Option(
        None,
        "--out-dir",
        "-o",
        help=(
            "Directory where reports will be written. "
            "Default: the scanned repository root (aitrace-report.html)."
        ),
    ),
    formats: Optional[List[OutputFormat]] = typer.Option(
        None,
        "--format",
        "-f",
        help=(
            "Optional machine-readable outputs in addition to the HTML report. "
            "Pass multiple -f values: cyclonedx, spdx, risk-md, mermaid, risk-json. "
            "Default: HTML report only."
        ),
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Also write risk-report.json, findings.json, and architecture graph files.",
    ),
    no_open: bool = typer.Option(
        False,
        "--no-open",
        help="Do not open the HTML report in a browser (useful for CI).",
    ),
    exploit: bool = typer.Option(
        False,
        "--exploit",
        help="Generate proof-of-concept exploit payloads from detected data flows.",
    ),
    verify: bool = typer.Option(
        False,
        "--verify",
        help=(
            "Semantically verify uncertain findings using an LLM. "
            "Requires a stored credential (run: aitrace configure) or env var. "
            "Makes API calls with redacted code context."
        ),
    ),
    verify_model: Optional[str] = typer.Option(
        None,
        "--verify-model",
        help=(
            "LLM model for verification. Any litellm model string is accepted, e.g. "
            "'claude-haiku-4-5-20251001', 'gpt-4o-mini', 'ollama/llama3'. "
            "Default: claude-haiku-4-5-20251001"
        ),
    ),
    secret_ref: Optional[str] = typer.Option(
        None,
        "--secret-ref",
        help=(
            "Resolve the API key from an external secret store. "
            "Formats: aws:secretsmanager:region:name, gcp:secretmanager:project/secret/versions/latest, "
            "azure:keyvault:https://vault.azure.net/secrets/name, "
            "hashicorp:vault:http://127.0.0.1:8200/v1/secret/data/aitrace, env:MY_VAR"
        ),
    ),
    dry_run_verify: bool = typer.Option(
        False,
        "--dry-run-verify",
        help=(
            "Show which findings would be sent for LLM verification and the redacted "
            "code context — without making any API calls."
        ),
    ),
) -> None:
    """
    Scan a local path or remote GitHub URL. Traces attack paths across files,
    detects AI security vulnerabilities, and writes aitrace-report.html
    (opens in browser). Use --exploit to generate PoC payloads from confirmed paths.
    """
    path, _tmp_clone = _clone_if_url(path)
    repo_root = resolve_repo_path(path)
    # When scanning a remote URL, default output goes to cwd, not inside the temp clone
    _is_remote = _tmp_clone is not None
    policy_path: Optional[Path]
    selected_formats: List[OutputFormat] = list(formats or [])

    if policy is not None:
        policy_path = Path(policy).expanduser().resolve()
    else:
        policy_path = find_default_policy(repo_root)

    typer.echo(f"Analyzing repository at: {repo_root}")
    if policy_path:
        typer.echo(f"Using policy file: {policy_path}")

    # --- Credential resolution for --verify --------------------------------
    provider_config = None
    if verify or dry_run_verify:
        chosen_model = verify_model or "claude-haiku-4-5-20251001"
        try:
            from core.features.credentials import ProviderConfig, detect_provider, resolve_api_key, CredentialNotFoundError
            provider = detect_provider(chosen_model)
            pc = ProviderConfig(provider=provider, model=chosen_model)
            try:
                provider_config = resolve_api_key(pc, secret_ref=secret_ref)
                if not pc.is_local:
                    typer.echo(
                        f"  ✓ Credential resolved via {provider_config.resolution_method} "
                        f"({provider_config.masked_key})"
                    )
            except CredentialNotFoundError as exc:
                typer.echo(f"  ✗ {exc}", err=True)
                if verify:
                    typer.echo("  Continuing without LLM verification.", err=True)
                    verify = False
                    dry_run_verify = False
        except ImportError:
            pass

    engine = AITraceEngine(repo_root)
    engine.verify_with_llm = verify
    if provider_config is not None:
        engine.provider_config = provider_config
    result = engine.analyze(policy_path=policy_path)

    # --- Dry-run verify mode -----------------------------------------------
    if dry_run_verify:
        _dry_run_verify(result, repo_root)
        return

    # Default output dir: explicit --out-dir > cwd (remote) > repo root (local)
    out_path = (
        Path(out_dir).expanduser().resolve()
        if out_dir
        else (Path.cwd() if _is_remote else repo_root)
    )
    out_path.mkdir(parents=True, exist_ok=True)

    architecture_result = result.architecture_result

    if OutputFormat.CYCLONEDX in selected_formats:
        cdx = to_cyclonedx_json(
            result.aibom,
            architecture_result=architecture_result,
            findings=result.findings,
            llm_usage=result.llm_usage,
            model_supply_chain=result.model_supply_chain,
        )
        (out_path / "aitrace-cyclonedx.json").write_text(json.dumps(cdx, indent=2), encoding="utf-8")
        typer.echo("Wrote CycloneDX BOM.")

    if OutputFormat.SPDX in selected_formats:
        spdx = to_spdx_json(
            result.aibom,
            architecture_result=architecture_result,
            findings=result.findings,
            llm_usage=result.llm_usage,
            model_supply_chain=result.model_supply_chain,
        )
        (out_path / "aitrace-spdx.json").write_text(json.dumps(spdx, indent=2), encoding="utf-8")
        typer.echo("Wrote SPDX document.")

    exploit_payloads: List[Any] = []
    verification_results: List[Any] = []
    rag_poison = None
    if exploit:
        from core.features.exploit_synthesizer import synthesize, exploits_to_markdown, print_exploits
        from core.features.finding_verifier import verify_statically, print_verification, verification_to_markdown
        exploit_payloads = synthesize(result)
        if exploit_payloads:
            verification_results = verify_statically(exploit_payloads, repo_root)

        from core.features.rag_poison_simulator import simulate as rag_simulate, poison_to_text
        rag_poison = rag_simulate(architecture_result)

    if OutputFormat.RISK_MD in selected_formats:
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
            architecture_graph=result.architecture_graph,
            attack_path_findings=result.attack_path_findings,
            pattern_analysis=result.pattern_analysis,
            crossfile_taint=result.crossfile_taint,
            llm_verification=result.llm_verification,
        )
        if exploit_payloads:
            risk_md += exploits_to_markdown(exploit_payloads)
            risk_md += verification_to_markdown(exploit_payloads, verification_results)
        (out_path / "aitrace-risk-report.md").write_text(risk_md, encoding="utf-8")
        typer.echo("Wrote risk report (Markdown).")

    if OutputFormat.MERMAID in selected_formats:
        mermaid_diagram = to_ai_component_mermaid(result.aibom, architecture_result)
        (out_path / "aitrace-component-diagram.mmd").write_text(mermaid_diagram, encoding="utf-8")
        typer.echo("Wrote AI component diagram (Mermaid).")

    # Verbose / risk-json: structured dumps
    if verbose or OutputFormat.RISK_JSON in selected_formats:
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
            architecture_graph=result.architecture_graph,
            attack_path_findings=result.attack_path_findings,
            pattern_analysis=result.pattern_analysis,
            crossfile_taint=result.crossfile_taint,
        )
        (out_path / "aitrace-risk-report.json").write_text(json.dumps(risk_json, indent=2), encoding="utf-8")
        typer.echo("Wrote risk report (JSON).")
        findings_json = to_findings_json(result.findings, architecture_result)
        (out_path / "aitrace-findings.json").write_text(json.dumps(findings_json, indent=2), encoding="utf-8")
        typer.echo("Wrote findings (JSON).")

    if verbose and result.architecture_graph:
        from core.analyzers.architecture_graph import architecture_graph_to_json, architecture_graph_to_mermaid
        (out_path / "aitrace-architecture-graph.json").write_text(
            architecture_graph_to_json(result.architecture_graph),
            encoding="utf-8",
        )
        (out_path / "aitrace-architecture-graph.mmd").write_text(
            architecture_graph_to_mermaid(result.architecture_graph),
            encoding="utf-8",
        )
        typer.echo("Wrote architecture graph (JSON and Mermaid).")

    if exploit_payloads:
        ver_map = {r.finding_id: r.to_dict() for r in verification_results}
        exploits_out = [
            {**p.to_dict(), "verification": ver_map.get(p.finding_id)}
            for p in exploit_payloads
        ]
        (out_path / "aitrace-exploits.json").write_text(
            json.dumps(exploits_out, indent=2),
            encoding="utf-8",
        )
        typer.echo(f"Wrote {len(exploit_payloads)} exploit payload(s) to aitrace-exploits.json.")
        print_exploits(exploit_payloads)
        if verification_results:
            typer.echo("\nStatic verification results:")
            print_verification(exploit_payloads, verification_results)

        if rag_poison:
            payload_path = out_path / "aitrace-rag-poison-payload.txt"
            payload_path.write_text(poison_to_text(rag_poison), encoding="utf-8")
            typer.echo(
                f"\nRAG pipeline detected ({rag_poison.detected_vector_store} + "
                f"{rag_poison.detected_embeddings})."
            )
            typer.echo(f"Wrote {len(rag_poison.variants)} poison variants to aitrace-rag-poison-payload.txt.")

    # Primary deliverable: complete HTML report (written last so Downloads links resolve)
    from core.exporters.html_report import to_html_report

    html_report = to_html_report(result, out_path, exploit_payloads or None, verification_results or None)
    html_path = out_path / "aitrace-report.html"
    html_path.write_text(html_report, encoding="utf-8")

    from core.exporters.html_report import filter_security_findings

    sev_counts: dict[str, int] = {}
    for f in filter_security_findings(result.findings or []):
        k = f.severity.value.upper()
        sev_counts[k] = sev_counts.get(k, 0) + 1
    sev_parts = [
        f"{sev_counts[s]} {s}"
        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        if sev_counts.get(s)
    ]
    typer.echo("")
    if sev_parts:
        typer.echo(f"Findings: {', '.join(sev_parts)}")
    typer.echo(f"Report: {html_path}")
    if not no_open:
        webbrowser.open(html_path.as_uri())

    if _tmp_clone:
        shutil.rmtree(_tmp_clone, ignore_errors=True)

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

ai_controls:
  # Fail build if code execution tools (PythonREPLTool, exec) are found
  no_code_execution_tools: false
  # Fail build if AI SDKs are used without being declared in requirements
  no_shadow_ai: false
  # Minimum trust score for MCP servers (0-100). Lower = more suspicious.
  mcp_trust_score_minimum: 60
  # Fail build if taint analysis confirms user input reaches external LLM
  no_user_data_to_external_llm: false
  # Fail build if hardcoded credentials are found
  no_hardcoded_credentials: true
  fail_build: true
"""
    target.write_text(template, encoding="utf-8")
    typer.echo(f"Wrote starter policy file to {target}")


def _dry_run_verify(result: Any, repo_root: Path) -> None:
    """Print which findings would be sent for LLM verification and their redacted context."""
    from core.features.llm_verifier import _select_findings, build_verification_context, _build_user_prompt
    from core.features.credentials.redactor import is_safe_to_send, count_redactions, redact_code_context

    pattern_analysis = getattr(result, "pattern_analysis", None)
    crossfile_taint = getattr(result, "crossfile_taint", None)

    if pattern_analysis is None:
        typer.echo("No pattern analysis results to verify.")
        return

    findings = getattr(pattern_analysis, "findings", [])
    selected = _select_findings(findings, 10)

    if not selected:
        typer.echo("No findings selected for verification (all confirmed/dismissed/low).")
        return

    typer.echo(f"\n{'=' * 70}")
    typer.echo(f"DRY RUN: {len(selected)} finding(s) would be sent for LLM verification")
    typer.echo(f"{'=' * 70}\n")

    class _EmptyTaint:
        call_graph: dict = {}

    taint = crossfile_taint or _EmptyTaint()

    for i, f in enumerate(selected, 1):
        context = build_verification_context(repo_root, f, taint)
        prompt = _build_user_prompt(f, context)
        safe, fired = is_safe_to_send(prompt)
        n_redacted = count_redactions(prompt, redact_code_context(prompt))
        typer.echo(f"[{i}] {f.vulnerability_id} — {f.title}")
        typer.echo(f"     File: {f.file}:{f.line or '?'}  Severity: {f.severity}")
        typer.echo(f"     Prompt size: ~{len(prompt) // 4} tokens")
        typer.echo(f"     Redactions applied: {n_redacted}")
        if not safe:
            typer.echo(f"     ⚠ Potential sensitive patterns detected: {', '.join(fired)}", err=True)
        else:
            typer.echo("     ✓ No sensitive patterns detected in prompt")
        typer.echo("")


@app.command()
def configure(
    provider: Optional[str] = typer.Option(
        None,
        "--provider",
        help="Provider to configure (e.g. anthropic, openai, google). Auto-detected if --model is set.",
    ),
    model: Optional[str] = typer.Option(
        None,
        "--model",
        help="Model string to infer provider from (e.g. claude-haiku-4-5-20251001).",
    ),
    delete: bool = typer.Option(
        False,
        "--delete",
        help="Delete the stored key for this provider instead of writing one.",
    ),
    list_providers: bool = typer.Option(
        False,
        "--list",
        help="List all providers with stored credentials.",
    ),
) -> None:
    """
    Securely store or manage API keys for LLM verification.

    Keys are stored in the OS keychain (macOS Keychain, Windows Credential Manager,
    or Linux libsecret). Never stored in plaintext or environment variables.

    Usage:
      aitrace configure --provider anthropic
      aitrace configure --model gpt-4o-mini
      aitrace configure --provider openai --delete
      aitrace configure --list
    """
    try:
        from core.features.credentials import detect_provider
        from core.features.credentials import keychain as _kc
        from core.features.credentials import config_store as _cs
    except ImportError as exc:
        typer.echo(f"Credentials subsystem unavailable: {exc}", err=True)
        raise typer.Exit(1)

    if list_providers:
        kc_available = _kc.is_available()
        stored_config = _cs.list_stored_providers()
        if not kc_available and not stored_config:
            typer.echo("No credentials stored (keyring not available and config store empty).")
            return
        typer.echo("Stored credentials:")
        if stored_config:
            for p in stored_config:
                typer.echo(f"  • {p}  (encrypted config store)")
        if kc_available:
            typer.echo("  (OS keychain entries cannot be enumerated — use --delete to remove)")
        return

    # Resolve provider name
    resolved_provider = provider
    if resolved_provider is None and model:
        resolved_provider = detect_provider(model)
        typer.echo(f"Detected provider: {resolved_provider}")
    if not resolved_provider:
        typer.echo("Specify --provider or --model to identify the provider.", err=True)
        raise typer.Exit(1)

    if delete:
        kc_ok = _kc.delete_key(resolved_provider)
        cs_ok = _cs.delete_provider_key(resolved_provider)
        if kc_ok or cs_ok:
            typer.echo(f"✓ Deleted stored key for '{resolved_provider}'.")
        else:
            typer.echo(f"No stored key found for '{resolved_provider}'.", err=True)
        return

    # Store new key
    import getpass
    try:
        key = getpass.getpass(f"Enter API key for '{resolved_provider}' (input hidden): ").strip()
    except (EOFError, KeyboardInterrupt):
        typer.echo("\nAborted.", err=True)
        raise typer.Exit(1)

    if not key:
        typer.echo("Empty key — nothing stored.", err=True)
        raise typer.Exit(1)

    # Validate display format: first 4 + *** + last 4
    display = f"{key[:4]}***{key[-4:]}" if len(key) >= 12 else f"{key[:2]}***"

    # Try keychain first, fall back to encrypted config store
    if _kc.is_available():
        if _kc.write_key(resolved_provider, key):
            # Clear key from local variable scope
            key = ""
            typer.echo(f"✓ Saved {display} to OS keychain for provider '{resolved_provider}'.")
            return

    if _cs.write_provider_key(resolved_provider, key):
        key = ""
        typer.echo(f"✓ Saved {display} to encrypted config store for provider '{resolved_provider}'.")
        return

    key = ""
    typer.echo(
        "Could not save to keychain or encrypted config store. "
        "Install 'keyring' or 'cryptography': pip install 'aitrace-cli[verify]'",
        err=True,
    )
    raise typer.Exit(1)


def main() -> None:
    app()


if __name__ == "__main__":
    main()

