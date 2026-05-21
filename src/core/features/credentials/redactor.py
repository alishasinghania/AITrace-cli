from __future__ import annotations

"""
Redacts sensitive values from code snippets before sending to external LLM APIs.
Applied to ALL cloud/managed API calls — never send raw code without redacting first.
"""

import re
from typing import List, Tuple

# ---------------------------------------------------------------------------
# Redaction patterns — ordered from most-specific to least-specific
# ---------------------------------------------------------------------------

# Each entry: (label, compiled_regex, replacement_template)
# $1 in replacement refers to an optional safe prefix group (e.g. variable name)

_PATTERNS: List[Tuple[str, re.Pattern, str]] = [
    # 1. OpenAI / Anthropic / generic sk- style keys
    (
        "api_key_sk",
        re.compile(r'(sk-[A-Za-z0-9]{4})[A-Za-z0-9\-_]{20,}([A-Za-z0-9]{4})', re.IGNORECASE),
        r'\1***\2',
    ),
    # 2. AWS access key IDs
    (
        "aws_access_key",
        re.compile(r'\b(AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b'),
        r'[REDACTED-AWS-KEY]',
    ),
    # 3. AWS secret access keys (= "value" or : "value" in configs)
    (
        "aws_secret",
        re.compile(
            r'(?i)(aws[_\s]*secret[_\s]*access[_\s]*key|aws[_\s]*secret)["\s]*[=:]["\s]*'
            r'([A-Za-z0-9/+]{40})\b'
        ),
        r'\1=[REDACTED]',
    ),
    # 4. PEM private key blocks
    (
        "pem_private_key",
        re.compile(
            r'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----'
            r'.*?'
            r'-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----',
            re.DOTALL,
        ),
        '[REDACTED-PRIVATE-KEY-BLOCK]',
    ),
    # 5. Bearer tokens in Authorization headers / strings
    (
        "bearer_token",
        re.compile(r'(Bearer\s+)[A-Za-z0-9\-_\.]{20,}', re.IGNORECASE),
        r'\1[REDACTED]',
    ),
    # 6. Database connection strings (postgres, mysql, mongodb, redis)
    (
        "db_connection_string",
        re.compile(
            r'(?i)(postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://'
            r'[^:\s@/]+:[^@\s/]+@[^\s\'"<>]+'
        ),
        r'[REDACTED-DB-URL]',
    ),
    # 7. Generic password/secret assignment  e.g. password = "abc123"
    (
        "password_assignment",
        re.compile(
            r'(?i)(password|passwd|secret|token|api[_\s]*key|auth[_\s]*token)'
            r'\s*[=:]\s*["\']([^"\']{6,})["\']'
        ),
        r'\1=[REDACTED]',
    ),
    # 8. GitHub personal access tokens (classic ghp_ and fine-grained github_pat_)
    (
        "github_token",
        re.compile(r'\b(ghp_|github_pat_)[A-Za-z0-9_]{20,}\b'),
        r'[REDACTED-GITHUB-TOKEN]',
    ),
    # 9. Google API keys
    (
        "google_api_key",
        re.compile(r'\bAIza[A-Za-z0-9\-_]{35}\b'),
        r'[REDACTED-GOOGLE-KEY]',
    ),
    # 10. Stripe API keys
    (
        "stripe_key",
        re.compile(r'\b(sk_live_|sk_test_|pk_live_|pk_test_)[A-Za-z0-9]{20,}\b'),
        r'[REDACTED-STRIPE-KEY]',
    ),
    # 11. HuggingFace tokens
    (
        "hf_token",
        re.compile(r'\bhf_[A-Za-z0-9]{20,}\b'),
        r'[REDACTED-HF-TOKEN]',
    ),
    # 12. Generic high-entropy base64/hex strings in assignment context
    #     Matches only when preceded by = or : (inside assignment), 32+ chars
    (
        "generic_secret_assignment",
        re.compile(
            r'(?i)(?:key|secret|token|credential|auth)\s*[=:]\s*["\']'
            r'([A-Za-z0-9+/=_\-]{32,})["\']'
        ),
        r'[REDACTED]',
    ),
]

# Replacement sentinel so we can count redactions
_REDACTED_SENTINEL = "[REDACTED"


def redact_code_context(code: str) -> str:
    """
    Apply all redaction patterns to *code* and return the sanitised string.
    Safe to call on empty strings or non-code text.
    """
    if not code:
        return code
    result = code
    for _label, pattern, replacement in _PATTERNS:
        result = pattern.sub(replacement, result)
    return result


def count_redactions(original: str, redacted: str) -> int:
    """Return the number of redaction sentinels introduced."""
    return redacted.count(_REDACTED_SENTINEL) - original.count(_REDACTED_SENTINEL)


def is_safe_to_send(code: str) -> Tuple[bool, List[str]]:
    """
    Check whether *code* appears safe to send to an external API.

    Returns:
        (safe, reasons) — safe is True only if zero patterns match.
        reasons lists the pattern labels that fired.
    """
    if not code:
        return True, []

    fired: List[str] = []
    for label, pattern, _ in _PATTERNS:
        if pattern.search(code):
            fired.append(label)

    return len(fired) == 0, fired
