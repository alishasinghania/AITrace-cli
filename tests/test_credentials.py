from __future__ import annotations

"""Tests for src/core/credentials/ — resolver, keychain, config_store."""

import os
import pytest
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# resolver.detect_provider
# ---------------------------------------------------------------------------

class TestDetectProvider:
    def test_claude_model(self):
        from core.features.credentials.resolver import detect_provider
        assert detect_provider("claude-haiku-4-5-20251001") == "anthropic"

    def test_gpt_model(self):
        from core.features.credentials.resolver import detect_provider
        assert detect_provider("gpt-4o-mini") == "openai"

    def test_gemini_model(self):
        from core.features.credentials.resolver import detect_provider
        assert detect_provider("gemini-pro") == "google"

    def test_ollama_model(self):
        from core.features.credentials.resolver import detect_provider
        assert detect_provider("ollama/llama3") == "ollama"

    def test_unknown_model(self):
        from core.features.credentials.resolver import detect_provider
        assert detect_provider("some-unknown-model") == "unknown"

    def test_mistral_model(self):
        from core.features.credentials.resolver import detect_provider
        assert detect_provider("mistral-7b-instruct") == "mistral"


# ---------------------------------------------------------------------------
# ProviderConfig properties
# ---------------------------------------------------------------------------

class TestProviderConfig:
    def test_is_local_ollama(self):
        from core.features.credentials.resolver import ProviderConfig
        pc = ProviderConfig(provider="ollama", model="ollama/llama3")
        assert pc.is_local is True
        assert pc.is_cloud is False

    def test_is_cloud_anthropic(self):
        from core.features.credentials.resolver import ProviderConfig
        pc = ProviderConfig(provider="anthropic", model="claude-haiku-4-5-20251001")
        assert pc.is_cloud is True
        assert pc.is_local is False

    def test_masked_key_long(self):
        from core.features.credentials.resolver import ProviderConfig
        pc = ProviderConfig(provider="anthropic", model="claude-haiku-4-5-20251001",
                            api_key="sk-ant-abc123xyz789abcdef")
        assert pc.masked_key == "sk-a***cdef"

    def test_masked_key_none(self):
        from core.features.credentials.resolver import ProviderConfig
        pc = ProviderConfig(provider="anthropic", model="claude-haiku-4-5-20251001")
        assert pc.masked_key == "(none)"

    def test_clear_key(self):
        from core.features.credentials.resolver import ProviderConfig
        pc = ProviderConfig(provider="anthropic", model="claude-haiku-4-5-20251001",
                            api_key="sk-secret")
        pc.clear_key()
        assert pc.api_key is None

    def test_is_managed_openrouter(self):
        from core.features.credentials.resolver import ProviderConfig
        pc = ProviderConfig(provider="openrouter", model="openrouter/gpt-4")
        assert pc.is_managed is True


# ---------------------------------------------------------------------------
# resolve_api_key — local provider (no key needed)
# ---------------------------------------------------------------------------

class TestResolveApiKeyLocal:
    def test_local_provider_no_key_needed(self):
        from core.features.credentials.resolver import ProviderConfig, resolve_api_key
        pc = ProviderConfig(provider="ollama", model="ollama/llama3")
        result = resolve_api_key(pc)
        assert result.resolution_method == "local-no-key"
        assert result.api_key is None


# ---------------------------------------------------------------------------
# resolve_api_key — env var fallback
# ---------------------------------------------------------------------------

class TestResolveApiKeyEnvVar:
    def test_resolves_from_env_var(self):
        from core.features.credentials.resolver import ProviderConfig, resolve_api_key

        # Patch out keychain and config store so they return None
        with patch("core.features.credentials.resolver._try_keychain", return_value=None), \
             patch("core.features.credentials.resolver._try_config_store", return_value=None), \
             patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key-from-env"}):
            pc = ProviderConfig(provider="anthropic", model="claude-haiku-4-5-20251001")
            result = resolve_api_key(pc, allow_prompt=False)
            assert result.api_key == "test-key-from-env"
            assert result.resolution_method == "env-var"

    def test_fails_when_no_key_anywhere(self):
        from core.features.credentials.resolver import ProviderConfig, resolve_api_key, CredentialNotFoundError

        with patch("core.features.credentials.resolver._try_keychain", return_value=None), \
             patch("core.features.credentials.resolver._try_config_store", return_value=None), \
             patch.dict(os.environ, {}, clear=True):
            pc = ProviderConfig(provider="anthropic", model="claude-haiku-4-5-20251001")
            # Remove env var if set
            env = {k: v for k, v in os.environ.items() if k != "ANTHROPIC_API_KEY"}
            with patch.dict(os.environ, env, clear=True):
                with pytest.raises(CredentialNotFoundError):
                    resolve_api_key(pc, allow_prompt=False)


# ---------------------------------------------------------------------------
# resolve_api_key — keychain priority
# ---------------------------------------------------------------------------

class TestResolveApiKeyKeychain:
    def test_keychain_takes_priority_over_env(self):
        from core.features.credentials.resolver import ProviderConfig, resolve_api_key

        with patch("core.features.credentials.resolver._try_keychain", return_value="keychain-key"), \
             patch.dict(os.environ, {"ANTHROPIC_API_KEY": "env-key"}):
            pc = ProviderConfig(provider="anthropic", model="claude-haiku-4-5-20251001")
            result = resolve_api_key(pc, allow_prompt=False)
            assert result.api_key == "keychain-key"
            assert result.resolution_method == "keychain"


# ---------------------------------------------------------------------------
# keychain wrapper (unit — mocks keyring)
# ---------------------------------------------------------------------------

class TestKeychainWrapper:
    def _make_mock_kr(self):
        kr = MagicMock()
        backend = MagicMock()
        backend.__class__.__name__ = "SecretService"
        kr.get_keyring.return_value = backend
        return kr

    def test_write_and_read(self):
        from core.features.credentials import keychain
        mock_kr = self._make_mock_kr()
        mock_kr.get_password.return_value = "test-api-key"

        with patch.object(keychain, "_keyring", return_value=mock_kr):
            ok = keychain.write_key("anthropic", "test-api-key")
            assert ok is True
            mock_kr.set_password.assert_called_once_with("aitrace-cli", "anthropic", "test-api-key")

            val = keychain.read_key("anthropic")
            assert val == "test-api-key"

    def test_delete(self):
        from core.features.credentials import keychain
        mock_kr = self._make_mock_kr()

        with patch.object(keychain, "_keyring", return_value=mock_kr):
            ok = keychain.delete_key("anthropic")
            assert ok is True
            mock_kr.delete_password.assert_called_once_with("aitrace-cli", "anthropic")

    def test_no_keyring_returns_none(self):
        from core.features.credentials import keychain
        with patch.object(keychain, "_keyring", return_value=None):
            assert keychain.read_key("anthropic") is None
            assert keychain.write_key("anthropic", "key") is False
            assert keychain.is_available() is False

    def test_is_available_false_for_fail_backend(self):
        from core.features.credentials import keychain
        mock_kr = MagicMock()
        backend = MagicMock()
        backend.__class__.__name__ = "FailKeyring"
        mock_kr.get_keyring.return_value = backend
        with patch.object(keychain, "_keyring", return_value=mock_kr):
            assert keychain.is_available() is False


# ---------------------------------------------------------------------------
# detect_provider edge cases
# ---------------------------------------------------------------------------

class TestDetectProviderEdgeCases:
    def test_empty_string(self):
        from core.features.credentials.resolver import detect_provider
        assert detect_provider("") == "unknown"

    def test_uppercase_model_name(self):
        from core.features.credentials.resolver import detect_provider
        # Provider map uses .lower() — should still match
        assert detect_provider("CLAUDE-HAIKU-4-5-20251001") == "anthropic"

    def test_groq_prefix(self):
        from core.features.credentials.resolver import detect_provider
        assert detect_provider("groq/llama-3.1-8b-instant") == "groq"


# ---------------------------------------------------------------------------
# ProviderConfig.masked_key edge cases
# ---------------------------------------------------------------------------

class TestMaskedKeyEdgeCases:
    def test_short_key_under_12_chars(self):
        from core.features.credentials.resolver import ProviderConfig
        pc = ProviderConfig(provider="anthropic", model="claude-haiku-4-5-20251001",
                            api_key="sk-ab")
        # Should not crash; uses short format
        masked = pc.masked_key
        assert "***" in masked
        assert "sk-ab" not in masked or masked.startswith("sk")  # prefix truncated

    def test_exactly_12_char_key(self):
        from core.features.credentials.resolver import ProviderConfig
        pc = ProviderConfig(provider="anthropic", model="claude-haiku-4-5-20251001",
                            api_key="sk-123456abcd")   # 14 chars — qualifies for long format
        masked = pc.masked_key
        assert "***" in masked


# ---------------------------------------------------------------------------
# keychain exception handling
# ---------------------------------------------------------------------------

class TestKeychainExceptionHandling:
    def test_write_key_survives_exception(self):
        from core.features.credentials import keychain
        mock_kr = MagicMock()
        mock_kr.set_password.side_effect = Exception("Keychain locked")
        with patch.object(keychain, "_keyring", return_value=mock_kr):
            result = keychain.write_key("anthropic", "test-key")
            assert result is False  # Should return False, not raise

    def test_read_key_survives_exception(self):
        from core.features.credentials import keychain
        mock_kr = MagicMock()
        mock_kr.get_password.side_effect = Exception("Keychain unavailable")
        with patch.object(keychain, "_keyring", return_value=mock_kr):
            result = keychain.read_key("anthropic")
            assert result is None  # Should return None, not raise

    def test_delete_key_survives_exception(self):
        from core.features.credentials import keychain
        mock_kr = MagicMock()
        mock_kr.delete_password.side_effect = Exception("Entry not found")
        with patch.object(keychain, "_keyring", return_value=mock_kr):
            result = keychain.delete_key("anthropic")
            assert result is False  # Should return False, not raise


# ---------------------------------------------------------------------------
# resolve_api_key — keychain exception falls through to env var
# ---------------------------------------------------------------------------

class TestResolveApiKeyFallthrough:
    def test_keychain_exception_falls_through_to_env(self):
        """When the keychain backend raises, _try_keychain returns None and
        resolve_api_key falls through to the env var."""
        from core.features.credentials.resolver import ProviderConfig, resolve_api_key
        from core.features.credentials import keychain as _kc

        with patch.object(_kc, "read_key", side_effect=RuntimeError("keychain exploded")), \
             patch("core.features.credentials.resolver._try_config_store", return_value=None), \
             patch.dict(os.environ, {"ANTHROPIC_API_KEY": "env-fallback-key"}):
            pc = ProviderConfig(provider="anthropic", model="claude-haiku-4-5-20251001")
            result = resolve_api_key(pc, allow_prompt=False)
            assert result.api_key == "env-fallback-key"
            assert result.resolution_method == "env-var"

    def test_config_store_takes_priority_over_env(self):
        from core.features.credentials.resolver import ProviderConfig, resolve_api_key

        with patch("core.features.credentials.resolver._try_keychain", return_value=None), \
             patch("core.features.credentials.resolver._try_config_store", return_value="config-store-key"), \
             patch.dict(os.environ, {"ANTHROPIC_API_KEY": "env-key"}):
            pc = ProviderConfig(provider="anthropic", model="claude-haiku-4-5-20251001")
            result = resolve_api_key(pc, allow_prompt=False)
            assert result.api_key == "config-store-key"
            assert result.resolution_method == "config-store"


# ---------------------------------------------------------------------------
# config_store (mocked cryptography)
# ---------------------------------------------------------------------------

class TestConfigStore:
    def test_write_read_roundtrip(self):
        """Write a key then read it back via the config store."""
        import tempfile
        from pathlib import Path
        from unittest.mock import patch as _patch

        try:
            from cryptography.fernet import Fernet  # noqa: F401
        except ImportError:
            pytest.skip("cryptography not installed")

        from core.features.credentials import config_store

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_cred = Path(tmpdir) / "credentials"
            # keychain is imported lazily inside _get_encryption_key — patch the
            # real module attributes, not config_store.keychain (which does not exist).
            with _patch.object(config_store, "_CRED_FILE", tmp_cred), \
                 _patch.object(config_store, "_CONFIG_DIR", Path(tmpdir)), \
                 _patch("core.features.credentials.keychain.read_key", return_value=None), \
                 _patch("core.features.credentials.keychain.write_key", return_value=False):
                ok = config_store.write_provider_key("openai", "sk-stored-securely")
                assert ok is True

                result = config_store.read_provider_key("openai")
                assert result == "sk-stored-securely"

    def test_read_nonexistent_key_returns_none(self):
        """Reading a provider that was never stored returns None."""
        try:
            from cryptography.fernet import Fernet  # noqa: F401
        except ImportError:
            pytest.skip("cryptography not installed")

        from core.features.credentials import config_store
        import tempfile
        from pathlib import Path
        from unittest.mock import patch as _patch

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_cred = Path(tmpdir) / "credentials"
            with _patch.object(config_store, "_CRED_FILE", tmp_cred), \
                 _patch.object(config_store, "_CONFIG_DIR", Path(tmpdir)), \
                 _patch("core.features.credentials.keychain.read_key", return_value=None), \
                 _patch("core.features.credentials.keychain.write_key", return_value=False):
                result = config_store.read_provider_key("nonexistent-provider")
                assert result is None

    def test_delete_removes_key(self):
        """After deleting, reading back returns None."""
        try:
            from cryptography.fernet import Fernet  # noqa: F401
        except ImportError:
            pytest.skip("cryptography not installed")

        from core.features.credentials import config_store
        import tempfile
        from pathlib import Path
        from unittest.mock import patch as _patch

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_cred = Path(tmpdir) / "credentials"
            with _patch.object(config_store, "_CRED_FILE", tmp_cred), \
                 _patch.object(config_store, "_CONFIG_DIR", Path(tmpdir)), \
                 _patch("core.features.credentials.keychain.read_key", return_value=None), \
                 _patch("core.features.credentials.keychain.write_key", return_value=False):
                config_store.write_provider_key("anthropic", "to-be-deleted")
                config_store.delete_provider_key("anthropic")
                assert config_store.read_provider_key("anthropic") is None

    def test_without_cryptography_returns_false(self):
        """When cryptography is not installed, write returns False gracefully."""
        import builtins
        real_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "cryptography.fernet":
                raise ImportError("No module named 'cryptography'")
            return real_import(name, *args, **kwargs)

        from core.features.credentials import config_store
        with patch("builtins.__import__", side_effect=mock_import), \
             patch.object(config_store, "_get_fernet", return_value=None):
            result = config_store.write_provider_key("anthropic", "some-key")
            assert result is False


# ---------------------------------------------------------------------------
# secrets_manager — SDK-not-installed errors
# ---------------------------------------------------------------------------

class TestSecretsManagerSDKMissing:
    def test_aws_without_boto3_raises_helpful_error(self):
        from core.features.credentials.secrets_manager import resolve_secret_ref, SecretResolutionError
        import builtins
        real_import = builtins.__import__

        def no_boto3(name, *args, **kwargs):
            if name == "boto3":
                raise ImportError("No module named 'boto3'")
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=no_boto3):
            with pytest.raises(SecretResolutionError, match="boto3"):
                resolve_secret_ref("aws:secretsmanager:us-east-1:my-secret")

    def test_gcp_without_sdk_raises_helpful_error(self):
        from core.features.credentials.secrets_manager import resolve_secret_ref, SecretResolutionError
        import builtins
        real_import = builtins.__import__

        def no_gcp(name, *args, **kwargs):
            if "google" in name:
                raise ImportError("No module named 'google'")
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=no_gcp):
            with pytest.raises(SecretResolutionError, match="google-cloud-secret-manager"):
                resolve_secret_ref("gcp:secretmanager:my-project/my-secret/versions/latest")

    def test_empty_secret_ref_raises(self):
        from core.features.credentials.secrets_manager import resolve_secret_ref, SecretResolutionError
        with pytest.raises(SecretResolutionError):
            resolve_secret_ref("")


# ---------------------------------------------------------------------------
# secrets_manager — env scheme
# ---------------------------------------------------------------------------

class TestSecretsManagerEnv:
    def test_resolves_env_scheme(self):
        from core.features.credentials.secrets_manager import resolve_secret_ref
        with patch.dict(os.environ, {"MY_TEST_SECRET": "hello-world"}):
            result = resolve_secret_ref("env:MY_TEST_SECRET")
            assert result == "hello-world"

    def test_raises_if_env_not_set(self):
        from core.features.credentials.secrets_manager import resolve_secret_ref, SecretResolutionError
        env = {k: v for k, v in os.environ.items() if k != "MY_NONEXISTENT_SECRET"}
        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(SecretResolutionError):
                resolve_secret_ref("env:MY_NONEXISTENT_SECRET")

    def test_raises_on_unknown_scheme(self):
        from core.features.credentials.secrets_manager import resolve_secret_ref, SecretResolutionError
        with pytest.raises(SecretResolutionError, match="Unknown secret scheme"):
            resolve_secret_ref("foobar:something")

    def test_raises_on_malformed_ref(self):
        from core.features.credentials.secrets_manager import resolve_secret_ref, SecretResolutionError
        with pytest.raises(SecretResolutionError):
            resolve_secret_ref("not-a-reference")


# ---------------------------------------------------------------------------
# resolve_api_key — secret_ref
# ---------------------------------------------------------------------------

class TestResolveApiKeySecretRef:
    def test_resolves_via_secret_ref(self):
        from core.features.credentials.resolver import ProviderConfig, resolve_api_key

        with patch("core.features.credentials.resolver._try_keychain", return_value=None), \
             patch("core.features.credentials.resolver._try_config_store", return_value=None), \
             patch("core.features.credentials.resolver._try_env_var", return_value=None), \
             patch("core.features.credentials.resolver._try_secret_ref", return_value="secret-ref-key"):
            pc = ProviderConfig(provider="anthropic", model="claude-haiku-4-5-20251001")
            result = resolve_api_key(pc, secret_ref="env:SOME_VAR", allow_prompt=False)
            assert result.api_key == "secret-ref-key"
            assert "secret-ref" in result.resolution_method
