from __future__ import annotations

"""
Central credential resolver for AITrace LLM verification.

Resolution priority (highest to lowest):
  1. OS Keychain  (via keychain.py)
  2. Encrypted config store  (via config_store.py)
  3. Environment variable   (with deprecation warning)
  4. Secret reference       (--secret-ref flag)
  5. Interactive prompt     (TTY only, never in CI)
  6. Keyless / local model  (no key needed)
  7. Raise CredentialNotFoundError

API keys are NEVER:
  - Logged in any form
  - Stored in plaintext
  - Passed as CLI flags
  - Stored as class attributes or module globals
"""

import os
import sys
from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# Provider detection helpers
# ---------------------------------------------------------------------------

# Map from model name prefix/substring → canonical provider name
_PROVIDER_MAP = {
    "gpt-": "openai",
    "o1-": "openai",
    "o3-": "openai",
    "o4-": "openai",
    "claude-": "anthropic",
    "gemini-": "google",
    "command": "cohere",
    "mistral": "mistral",
    "llama": "meta",
    "ollama/": "ollama",
    "openrouter/": "openrouter",
    "together/": "together",
    "groq/": "groq",
    "grok-": "xai",
    "xai/": "xai",
    "xai-": "xai",
    "deepseek": "deepseek",
    "qwen": "dashscope",
    "kimi": "moonshot",
    "moonshot": "moonshot",
}

# Providers that require an API key
_CLOUD_PROVIDERS = {
    "openai", "anthropic", "google", "cohere", "mistral", "openrouter",
    "together", "groq", "deepseek", "xai", "dashscope", "moonshot", "perplexity",
}

# Providers that are local (no key needed)
_LOCAL_PROVIDERS = {"ollama", "meta"}

# Env variable names per provider
_ENV_VAR_MAP = {
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "google": "GOOGLE_API_KEY",
    "cohere": "COHERE_API_KEY",
    "mistral": "MISTRAL_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
    "together": "TOGETHER_API_KEY",
    "groq": "GROQ_API_KEY",
    "deepseek": "DEEPSEEK_API_KEY",
    "xai": "XAI_API_KEY",
    "dashscope": "DASHSCOPE_API_KEY",
    "moonshot": "MOONSHOT_API_KEY",
    "perplexity": "PERPLEXITY_API_KEY",
}


def detect_provider(model: str) -> str:
    """Infer provider name from a model identifier string."""
    lower = model.lower()
    # First pass: exact prefix match (most specific)
    for prefix, provider in _PROVIDER_MAP.items():
        if lower.startswith(prefix):
            return provider
    # Second pass: substring match (less specific)
    for prefix, provider in _PROVIDER_MAP.items():
        if prefix in lower:
            return provider
    return "unknown"


# ---------------------------------------------------------------------------
# ProviderConfig — the only object the LLM verifier receives
# ---------------------------------------------------------------------------

@dataclass
class ProviderConfig:
    """
    Carries all configuration needed to make one LLM API call.
    The api_key field is populated only at call time and should be
    cleared immediately after use.

    Never store this object beyond the scope of a single verify() call.
    """
    provider: str
    model: str
    base_url: Optional[str] = None

    # Resolved at runtime — cleared after use
    api_key: Optional[str] = field(default=None, repr=False)

    # Resolution metadata (for display only — never contains the key)
    resolution_method: str = "unresolved"

    @property
    def is_local(self) -> bool:
        return self.provider in _LOCAL_PROVIDERS

    @property
    def is_cloud(self) -> bool:
        return self.provider in _CLOUD_PROVIDERS

    @property
    def is_managed(self) -> bool:
        """True if routed through a proxy/aggregator (openrouter, together, etc.)"""
        return self.provider in {"openrouter", "together", "groq"}

    @property
    def masked_key(self) -> str:
        """Safe display format: first 4 + *** + last 4 chars."""
        k = self.api_key or ""
        if len(k) >= 12:
            return f"{k[:4]}***{k[-4:]}"
        if k:
            return f"{k[:2]}***"
        return "(none)"

    def clear_key(self) -> None:
        """Zero out the key reference after use."""
        self.api_key = None


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class CredentialNotFoundError(Exception):
    """Raised when no credential can be resolved for a given provider."""


# ---------------------------------------------------------------------------
# Main resolver
# ---------------------------------------------------------------------------

def resolve_api_key(
    provider_config: ProviderConfig,
    secret_ref: Optional[str] = None,
    allow_prompt: bool = True,
) -> ProviderConfig:
    """
    Resolve the API key for *provider_config* and return an updated copy
    with api_key populated and resolution_method set.

    The key is resolved through the priority chain and stored only in the
    returned ProviderConfig — never in a global, class attribute, or log.

    Args:
        provider_config:  ProviderConfig with provider/model set (no key yet)
        secret_ref:       Optional secret reference string (--secret-ref value)
        allow_prompt:     Whether to offer interactive prompt (False in CI)

    Returns:
        Updated ProviderConfig with api_key set.

    Raises:
        CredentialNotFoundError: if no credential can be resolved.
    """
    if provider_config.is_local:
        provider_config.resolution_method = "local-no-key"
        return provider_config

    provider = provider_config.provider

    # 1. OS Keychain
    key = _try_keychain(provider)
    if key:
        provider_config.api_key = key
        provider_config.resolution_method = "keychain"
        return provider_config

    # 2. Encrypted config store
    key = _try_config_store(provider)
    if key:
        provider_config.api_key = key
        provider_config.resolution_method = "config-store"
        return provider_config

    # 3. Environment variable (with warning)
    key = _try_env_var(provider)
    if key:
        provider_config.api_key = key
        provider_config.resolution_method = "env-var"
        _warn_env_var(provider)
        return provider_config

    # 4. Secret reference
    if secret_ref:
        key = _try_secret_ref(secret_ref)
        if key:
            provider_config.api_key = key
            provider_config.resolution_method = f"secret-ref:{secret_ref.split(':')[0]}"
            return provider_config

    # 5. Interactive prompt (TTY only)
    if allow_prompt and sys.stdin.isatty():
        key = _try_interactive_prompt(provider)
        if key:
            provider_config.api_key = key
            provider_config.resolution_method = "interactive-prompt"
            return provider_config

    # 6. Check if keyless mode is acceptable (local/unknown provider)
    if not provider_config.is_cloud:
        provider_config.resolution_method = "keyless"
        return provider_config

    # 7. Fail
    env_var = _ENV_VAR_MAP.get(provider, f"{provider.upper()}_API_KEY")
    raise CredentialNotFoundError(
        f"No API key found for provider '{provider}'.\n"
        f"Options:\n"
        f"  • Run: aitrace configure --provider {provider}\n"
        f"  • Set env var: {env_var}  (less secure)\n"
        f"  • Use --secret-ref aws:secretsmanager:region:secret-name\n"
        f"  • Use a local model: --verify-model ollama/llama3"
    )


# ---------------------------------------------------------------------------
# Step implementations — each returns the key or None
# ---------------------------------------------------------------------------

def _try_keychain(provider: str) -> Optional[str]:
    try:
        from . import keychain
        return keychain.read_key(provider)
    except Exception:
        return None


def _try_config_store(provider: str) -> Optional[str]:
    try:
        from . import config_store
        return config_store.read_provider_key(provider)
    except Exception:
        return None


def _try_env_var(provider: str) -> Optional[str]:
    env_var = _ENV_VAR_MAP.get(provider)
    if not env_var:
        return None
    return os.environ.get(env_var) or None


def _try_secret_ref(ref: str) -> Optional[str]:
    try:
        from .secrets_manager import resolve_secret_ref, SecretResolutionError
        return resolve_secret_ref(ref)
    except Exception:
        return None


def _try_interactive_prompt(provider: str) -> Optional[str]:
    """Prompt user for API key on TTY. Key is not echoed."""
    import getpass
    env_var = _ENV_VAR_MAP.get(provider, f"{provider.upper()}_API_KEY")
    try:
        key = getpass.getpass(
            f"Enter API key for '{provider}' (input hidden): "
        ).strip()
        if not key:
            return None
        # Offer to save to keychain
        try:
            from . import keychain
            if keychain.is_available():
                save = input("Save to OS keychain for future use? [y/N] ").strip().lower()
                if save == "y":
                    keychain.write_key(provider, key)
                    print(f"  ✓ Saved to keychain (provider: {provider})")
        except Exception:
            pass
        return key
    except (EOFError, KeyboardInterrupt):
        return None


def _warn_env_var(provider: str) -> None:
    env_var = _ENV_VAR_MAP.get(provider, f"{provider.upper()}_API_KEY")
    print(
        f"  ⚠  Using {env_var} from environment. "
        "For better security, run: aitrace configure --provider "
        f"{provider}",
        file=sys.stderr,
    )
