from __future__ import annotations

"""Tests for src/core/credentials/redactor.py"""

import pytest
from core.credentials.redactor import (
    redact_code_context,
    count_redactions,
    is_safe_to_send,
)


# ---------------------------------------------------------------------------
# redact_code_context
# ---------------------------------------------------------------------------

class TestRedactCodeContext:
    def test_empty_string(self):
        assert redact_code_context("") == ""

    def test_clean_code_unchanged(self):
        code = "def hello():\n    return 'world'\n"
        assert redact_code_context(code) == code

    def test_redacts_sk_api_key(self):
        code = "key = 'sk-abcdefghijklmnopqrstuvwxyz1234567890abcd'"
        result = redact_code_context(code)
        # The middle portion of the key should be gone; only prefix+suffix preserved
        assert "abcdefghijklmnopqrstuvwxyz1234567890" not in result
        assert "***" in result

    def test_redacts_aws_access_key(self):
        code = "access_key = 'AKIAIOSFODNN7EXAMPLE'"
        result = redact_code_context(code)
        assert "AKIAIOSFODNN7EXAMPLE" not in result

    def test_redacts_pem_private_key(self):
        code = (
            "key = '''\n"
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA2a2rwplBQLF29amygykEMmYz0+Kcj3bKBp29P2rFj7sQqPk\n"
            "-----END RSA PRIVATE KEY-----\n"
            "'''"
        )
        result = redact_code_context(code)
        assert "MIIEowIBAAKCAQEA" not in result
        assert "REDACTED" in result

    def test_redacts_bearer_token(self):
        code = "headers = {'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'}"
        result = redact_code_context(code)
        assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in result

    def test_redacts_db_connection_string(self):
        code = "url = 'postgresql://admin:sup3rS3cr3t@db.example.com:5432/prod'"
        result = redact_code_context(code)
        assert "sup3rS3cr3t" not in result

    def test_redacts_password_assignment(self):
        code = "password = 'my_secret_password_123'"
        result = redact_code_context(code)
        assert "my_secret_password_123" not in result

    def test_redacts_github_token(self):
        code = "token = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef'"
        result = redact_code_context(code)
        assert "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ" not in result

    def test_redacts_google_api_key(self):
        code = "key = 'AIzaSyBxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'"
        result = redact_code_context(code)
        assert "AIzaSyBxxxxxxxxxxxxxx" not in result

    def test_redacts_stripe_key(self):
        code = "sk = 'sk_live_ABCDEFGHIJKLMNOPQRST'"
        result = redact_code_context(code)
        assert "sk_live_ABCDEFGHIJ" not in result

    def test_redacts_hf_token(self):
        code = "hf_token = 'hf_ABCDEFGHIJKLMNOPQRSTUVWXYZabcd'"
        result = redact_code_context(code)
        assert "hf_ABCDEFGHIJKLMNOP" not in result

    def test_multiple_secrets_in_same_file(self):
        code = (
            "api_key = 'sk-abcdefghijklmnop12345678901234567890abcdef'\n"
            "db_url = 'postgres://user:pass123@host/db'\n"
            "github = 'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'\n"
        )
        result = redact_code_context(code)
        assert "abcdefghijklmnop" not in result
        assert "pass123" not in result
        assert "ghp_xxxx" not in result

    def test_preserves_non_secret_code(self):
        code = (
            "import os\n"
            "def get_key():\n"
            "    return os.environ.get('API_KEY')\n"
        )
        result = redact_code_context(code)
        assert "import os" in result
        assert "def get_key" in result
        assert "os.environ.get" in result

    def test_redacts_key_inside_comment(self):
        # Secrets in comments are still in the text the LLM reads — must be redacted
        code = "# old key: AKIAIOSFODNN7EXAMPLE\napi_key = os.environ.get('KEY')"
        result = redact_code_context(code)
        assert "AKIAIOSFODNN7EXAMPLE" not in result

    def test_redacts_key_in_url_context(self):
        # Key embedded in a URL-like string (e.g. passed as a query param)
        code = "url = 'https://api.example.com?key=AKIAIOSFODNN7EXAMPLE'"
        result = redact_code_context(code)
        assert "AKIAIOSFODNN7EXAMPLE" not in result

    def test_key_at_start_of_string(self):
        # No leading context — pattern must still fire
        code = "AKIAIOSFODNN7EXAMPLE"
        result = redact_code_context(code)
        assert "AKIAIOSFODNN7EXAMPLE" not in result

    def test_redact_then_check_is_safe(self):
        # Round-trip: after redaction, is_safe_to_send should report True
        code = (
            "api_key = 'sk-abcdefghijklmnopqrstuvwxyz1234567890abcd'\n"
            "token = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef'\n"
        )
        redacted = redact_code_context(code)
        safe, fired = is_safe_to_send(redacted)
        assert safe is True, f"Still unsafe after redaction — patterns fired: {fired}"

    def test_unicode_content_handled(self):
        code = "# こんにちは\ndef greet():\n    return '你好'\n"
        result = redact_code_context(code)
        assert "こんにちは" in result  # non-secret Unicode preserved
        assert "greet" in result


# ---------------------------------------------------------------------------
# count_redactions
# ---------------------------------------------------------------------------

class TestCountRedactions:
    def test_no_redactions(self):
        clean = "def foo(): return 1"
        assert count_redactions(clean, clean) == 0

    def test_counts_single_redaction(self):
        original = "key = 'AKIAIOSFODNN7EXAMPLE'"
        redacted = redact_code_context(original)
        assert count_redactions(original, redacted) >= 1

    def test_counts_multiple_redactions(self):
        # Both patterns produce [REDACTED... sentinels
        original = (
            "key1 = 'AKIAIOSFODNN7EXAMPLE'\n"
            "token = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef'\n"
        )
        redacted = redact_code_context(original)
        assert count_redactions(original, redacted) >= 2

    def test_original_with_existing_redacted_marker(self):
        # If the original already has [REDACTED, count_redactions should not
        # double-count it — result count should be >= original count
        original = "# [REDACTED] placeholder\nkey = 'AKIAIOSFODNN7EXAMPLE'"
        redacted = redact_code_context(original)
        n = count_redactions(original, redacted)
        # Original has 1 sentinel, redacted adds at least 1 more
        assert n >= 1

    def test_identical_strings_always_zero(self):
        # count_redactions(x, x) == 0 for any string
        for s in ["", "clean code", "key=[REDACTED-SOME-THING]"]:
            assert count_redactions(s, s) == 0


# ---------------------------------------------------------------------------
# is_safe_to_send
# ---------------------------------------------------------------------------

class TestIsSafeToSend:
    def test_safe_clean_code(self):
        code = "def add(a, b):\n    return a + b\n"
        safe, fired = is_safe_to_send(code)
        assert safe is True
        assert fired == []

    def test_empty_string_is_safe(self):
        safe, fired = is_safe_to_send("")
        assert safe is True

    def test_detects_aws_key(self):
        code = "key = 'AKIAIOSFODNN7EXAMPLE'"
        safe, fired = is_safe_to_send(code)
        assert safe is False
        assert "aws_access_key" in fired

    def test_detects_sk_key(self):
        code = "api_key = 'sk-abcdefghijklmnopqrstuvwxyz1234567890abcd'"
        safe, fired = is_safe_to_send(code)
        assert safe is False
        assert "api_key_sk" in fired

    def test_detects_password(self):
        code = "password = 'super_secret_password'"
        safe, fired = is_safe_to_send(code)
        assert safe is False
        assert "password_assignment" in fired

    def test_detects_multiple_patterns(self):
        code = (
            "key = 'AKIAIOSFODNN7EXAMPLE'\n"
            "secret = 'sk-abcdefghijklmnopqrstuvwxyz1234567890abcd'\n"
        )
        safe, fired = is_safe_to_send(code)
        assert safe is False
        assert len(fired) >= 2

    def test_env_var_reference_is_safe(self):
        # Just reading from env — not a secret itself
        code = "key = os.environ.get('ANTHROPIC_API_KEY')"
        safe, fired = is_safe_to_send(code)
        assert safe is True

    def test_returns_list_not_set(self):
        code = "key = 'AKIAIOSFODNN7EXAMPLE'"
        safe, fired = is_safe_to_send(code)
        assert isinstance(fired, list)

    def test_safe_returns_empty_list(self):
        code = "x = 1 + 2"
        safe, fired = is_safe_to_send(code)
        assert fired == []
        assert safe is True

    def test_already_redacted_text_is_safe(self):
        # Text that has already been through redact_code_context should pass
        original = "api_key = 'sk-abcdefghijklmnopqrstuvwxyz1234567890abcd'"
        redacted = redact_code_context(original)
        safe, fired = is_safe_to_send(redacted)
        assert safe is True, f"Redacted text still flagged: {fired}"
