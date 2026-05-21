from __future__ import annotations

"""
AITrace credentials subsystem.

Public API surface — import only these names from outside this package.
"""

from .resolver import (
    CredentialNotFoundError,
    ProviderConfig,
    detect_provider,
    resolve_api_key,
)
from .redactor import redact_code_context, count_redactions, is_safe_to_send

__all__ = [
    "CredentialNotFoundError",
    "ProviderConfig",
    "detect_provider",
    "resolve_api_key",
    "redact_code_context",
    "count_redactions",
    "is_safe_to_send",
]
