from __future__ import annotations

"""
Resolves secret references from external secret stores.

Supported reference formats (passed via --secret-ref):
  aws:secretsmanager:us-east-1:my-secret-name[#json-key]
  gcp:secretmanager:my-project/my-secret/versions/latest
  azure:keyvault:https://vault.azure.net/secrets/my-secret
  hashicorp:vault:http://127.0.0.1:8200/v1/secret/data/aitrace
  env:MY_ENV_VAR_NAME

All provider SDK imports are lazy — missing SDKs raise SecretResolutionError
with a clear installation hint rather than an ImportError at module load.
"""

import os
from typing import Optional


class SecretResolutionError(Exception):
    """Raised when a secret reference cannot be resolved."""


def resolve_secret_ref(ref: str) -> str:
    """
    Resolve a secret reference string and return the plaintext secret value.

    Raises SecretResolutionError if the reference is malformed or resolution fails.
    """
    if not ref or ":" not in ref:
        raise SecretResolutionError(f"Unrecognised secret reference format: {ref!r}")

    scheme, _, rest = ref.partition(":")

    if scheme == "env":
        return _resolve_env(rest)
    if scheme == "aws":
        return _resolve_aws(rest)
    if scheme == "gcp":
        return _resolve_gcp(rest)
    if scheme == "azure":
        return _resolve_azure(rest)
    if scheme in ("hashicorp", "vault"):
        return _resolve_vault(rest)

    raise SecretResolutionError(
        f"Unknown secret scheme {scheme!r}. "
        "Supported: env, aws, gcp, azure, hashicorp/vault"
    )


# ---------------------------------------------------------------------------
# Env var (simplest — no SDK required)
# ---------------------------------------------------------------------------

def _resolve_env(var_name: str) -> str:
    value = os.environ.get(var_name.strip())
    if not value:
        raise SecretResolutionError(
            f"Environment variable {var_name!r} is not set or empty."
        )
    return value


# ---------------------------------------------------------------------------
# AWS Secrets Manager
# ---------------------------------------------------------------------------

def _resolve_aws(rest: str) -> str:
    """rest = "secretsmanager:region:secret-name[#json-key]" """
    try:
        import boto3  # type: ignore
        from botocore.exceptions import ClientError  # type: ignore
    except ImportError:
        raise SecretResolutionError(
            "boto3 is required for AWS secret references. "
            "Install it with: pip install boto3"
        )

    parts = rest.split(":", 2)
    if len(parts) < 3 or parts[0] != "secretsmanager":
        raise SecretResolutionError(
            f"Invalid AWS secret ref. Expected: aws:secretsmanager:region:secret-name. Got: aws:{rest}"
        )

    region = parts[1]
    name_and_key = parts[2]

    json_key: Optional[str] = None
    if "#" in name_and_key:
        name_and_key, json_key = name_and_key.rsplit("#", 1)

    try:
        client = boto3.client("secretsmanager", region_name=region)
        response = client.get_secret_value(SecretId=name_and_key)
    except ClientError as exc:
        raise SecretResolutionError(f"AWS Secrets Manager error: {exc}") from exc

    secret = response.get("SecretString") or response.get("SecretBinary", b"").decode()

    if json_key:
        import json
        try:
            data = json.loads(secret)
            if json_key not in data:
                raise SecretResolutionError(
                    f"JSON key {json_key!r} not found in secret {name_and_key!r}"
                )
            secret = data[json_key]
        except (json.JSONDecodeError, TypeError) as exc:
            raise SecretResolutionError(
                f"Could not parse AWS secret as JSON to extract key {json_key!r}: {exc}"
            ) from exc

    return secret


# ---------------------------------------------------------------------------
# GCP Secret Manager
# ---------------------------------------------------------------------------

def _resolve_gcp(rest: str) -> str:
    """rest = "secretmanager:project/secret/versions/version" """
    try:
        from google.cloud import secretmanager  # type: ignore
    except ImportError:
        raise SecretResolutionError(
            "google-cloud-secret-manager is required for GCP secret references. "
            "Install it with: pip install google-cloud-secret-manager"
        )

    _, _, resource_name = rest.partition(":")
    resource_name = resource_name.strip()
    if not resource_name.startswith("projects/"):
        # Accept shorthand: project/secret/versions/version
        parts = resource_name.split("/")
        if len(parts) == 3:
            resource_name = f"projects/{parts[0]}/secrets/{parts[1]}/versions/{parts[2]}"
        elif len(parts) == 4:
            resource_name = f"projects/{parts[0]}/secrets/{parts[1]}/versions/{parts[3]}"

    try:
        client = secretmanager.SecretManagerServiceClient()
        response = client.access_secret_version(name=resource_name)
        return response.payload.data.decode("utf-8")
    except Exception as exc:
        raise SecretResolutionError(f"GCP Secret Manager error: {exc}") from exc


# ---------------------------------------------------------------------------
# Azure Key Vault
# ---------------------------------------------------------------------------

def _resolve_azure(rest: str) -> str:
    """rest = "keyvault:https://vault.azure.net/secrets/name[/version]" """
    try:
        from azure.keyvault.secrets import SecretClient  # type: ignore
        from azure.identity import DefaultAzureCredential  # type: ignore
    except ImportError:
        raise SecretResolutionError(
            "azure-keyvault-secrets and azure-identity are required for Azure secret references. "
            "Install with: pip install azure-keyvault-secrets azure-identity"
        )

    _, _, url = rest.partition(":")
    url = url.strip()

    # Parse: https://vault.azure.net/secrets/secret-name[/version]
    from urllib.parse import urlparse
    parsed = urlparse(url)
    vault_url = f"{parsed.scheme}://{parsed.netloc}"
    path_parts = [p for p in parsed.path.split("/") if p]
    # path_parts: ["secrets", "name"] or ["secrets", "name", "version"]
    if len(path_parts) < 2 or path_parts[0] != "secrets":
        raise SecretResolutionError(
            f"Invalid Azure Key Vault URL. Expected .../secrets/name[/version]. Got: {url}"
        )

    secret_name = path_parts[1]
    secret_version = path_parts[2] if len(path_parts) > 2 else None

    try:
        credential = DefaultAzureCredential()
        client = SecretClient(vault_url=vault_url, credential=credential)
        secret = client.get_secret(secret_name, version=secret_version)
        return secret.value
    except Exception as exc:
        raise SecretResolutionError(f"Azure Key Vault error: {exc}") from exc


# ---------------------------------------------------------------------------
# HashiCorp Vault
# ---------------------------------------------------------------------------

def _resolve_vault(rest: str) -> str:
    """rest = "vault:http://127.0.0.1:8200/v1/secret/data/path[#json-key]" """
    try:
        import hvac  # type: ignore
    except ImportError:
        raise SecretResolutionError(
            "hvac is required for HashiCorp Vault secret references. "
            "Install it with: pip install hvac"
        )

    _, _, url = rest.partition(":")
    url = url.strip()

    json_key: Optional[str] = None
    if "#" in url:
        url, json_key = url.rsplit("#", 1)

    # Extract vault address and path from URL
    from urllib.parse import urlparse
    parsed = urlparse(url)
    vault_addr = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path.lstrip("/")  # e.g. "v1/secret/data/aitrace"

    token = os.environ.get("VAULT_TOKEN")
    if not token:
        raise SecretResolutionError(
            "VAULT_TOKEN environment variable must be set for HashiCorp Vault resolution."
        )

    try:
        client = hvac.Client(url=vault_addr, token=token)
        if not client.is_authenticated():
            raise SecretResolutionError("HashiCorp Vault: authentication failed (check VAULT_TOKEN)")

        # Strip "v1/" prefix for hvac read
        if path.startswith("v1/"):
            path = path[3:]

        response = client.read(path)
        if response is None:
            raise SecretResolutionError(f"HashiCorp Vault: no secret at path {path!r}")

        data = response.get("data", {})
        # KV v2 wraps in an extra "data" key
        if "data" in data and isinstance(data["data"], dict):
            data = data["data"]

        if json_key:
            if json_key not in data:
                raise SecretResolutionError(
                    f"HashiCorp Vault: key {json_key!r} not found at path {path!r}"
                )
            return str(data[json_key])

        if len(data) == 1:
            return str(next(iter(data.values())))

        raise SecretResolutionError(
            f"HashiCorp Vault: multiple keys at {path!r} — specify one with #key suffix"
        )
    except SecretResolutionError:
        raise
    except Exception as exc:
        raise SecretResolutionError(f"HashiCorp Vault error: {exc}") from exc
