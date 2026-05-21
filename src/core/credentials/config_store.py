from __future__ import annotations

"""
Encrypted credential store at ~/.aitrace/credentials.

Encryption key is derived from the OS keychain (via keychain.py).
If keyring is unavailable, falls back to a machine-derived key (less secure).
The file is never written in plaintext — Fernet symmetric encryption is used.

This module is intentionally NOT imported at the top of any public API.
Only resolver.py uses it, lazily, when other resolution methods fail.
"""

import base64
import hashlib
import json
import os
import platform
from pathlib import Path
from typing import Dict, Optional

_CONFIG_DIR = Path.home() / ".aitrace"
_CRED_FILE = _CONFIG_DIR / "credentials"
_KEYCHAIN_SERVICE = "aitrace-cli"
_KEYCHAIN_ACCOUNT = "config-encryption-key"


# ---------------------------------------------------------------------------
# Encryption helpers (lazy Fernet import)
# ---------------------------------------------------------------------------

def _get_fernet():
    """Lazy import of cryptography.fernet.Fernet. Returns None if unavailable."""
    try:
        from cryptography.fernet import Fernet  # type: ignore
        return Fernet
    except ImportError:
        return None


def _derive_machine_key() -> bytes:
    """
    Derive a deterministic key from machine-specific attributes.
    Used only as last resort when keyring is unavailable.
    Less secure than a random keychain-stored key.
    """
    machine_id = (
        platform.node()
        + platform.machine()
        + str(os.getuid() if hasattr(os, "getuid") else 0)
    )
    digest = hashlib.sha256(machine_id.encode()).digest()
    return base64.urlsafe_b64encode(digest)


def _get_encryption_key() -> Optional[bytes]:
    """
    Retrieve or generate the Fernet encryption key.
    Priority: keychain → machine-derived key.
    """
    from . import keychain

    stored = keychain.read_key(_KEYCHAIN_ACCOUNT)
    if stored:
        return stored.encode()

    # Generate a new random key and store in keychain
    Fernet = _get_fernet()
    if Fernet is None:
        return _derive_machine_key()

    key = Fernet.generate_key()
    if keychain.write_key(_KEYCHAIN_ACCOUNT, key.decode()):
        return key
    # Keychain unavailable — use machine key
    return _derive_machine_key()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def write_provider_key(provider: str, api_key: str) -> bool:
    """
    Encrypt and persist an API key for *provider* in ~/.aitrace/credentials.
    Returns True on success.
    NEVER writes plaintext to disk.
    """
    Fernet = _get_fernet()
    if Fernet is None:
        # cryptography package not installed; skip config file storage
        return False

    key = _get_encryption_key()
    if key is None:
        return False

    try:
        _CONFIG_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)

        # Load existing store (decrypt first)
        store = _load_store(Fernet, key)
        store[provider] = api_key

        # Re-encrypt the entire store
        f = Fernet(key)
        plaintext = json.dumps(store).encode()
        ciphertext = f.encrypt(plaintext)
        _CRED_FILE.write_bytes(ciphertext)
        _CRED_FILE.chmod(0o600)
        return True
    except Exception:
        return False


def read_provider_key(provider: str) -> Optional[str]:
    """
    Read and decrypt the API key for *provider* from ~/.aitrace/credentials.
    Returns None if not found or decryption fails.
    """
    Fernet = _get_fernet()
    if Fernet is None or not _CRED_FILE.exists():
        return None

    key = _get_encryption_key()
    if key is None:
        return None

    try:
        store = _load_store(Fernet, key)
        return store.get(provider)
    except Exception:
        return None


def delete_provider_key(provider: str) -> bool:
    """Remove a provider key from the encrypted config store."""
    Fernet = _get_fernet()
    if Fernet is None or not _CRED_FILE.exists():
        return False

    key = _get_encryption_key()
    if key is None:
        return False

    try:
        store = _load_store(Fernet, key)
        if provider not in store:
            return False
        del store[provider]
        f = Fernet(key)
        ciphertext = f.encrypt(json.dumps(store).encode())
        _CRED_FILE.write_bytes(ciphertext)
        return True
    except Exception:
        return False


def list_stored_providers() -> list:
    """Return list of provider names in the encrypted config store."""
    Fernet = _get_fernet()
    if Fernet is None or not _CRED_FILE.exists():
        return []

    key = _get_encryption_key()
    if key is None:
        return []

    try:
        store = _load_store(Fernet, key)
        return list(store.keys())
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _load_store(Fernet, key: bytes) -> Dict[str, str]:
    """Decrypt and return the credential store dict."""
    if not _CRED_FILE.exists():
        return {}
    try:
        f = Fernet(key)
        ciphertext = _CRED_FILE.read_bytes()
        plaintext = f.decrypt(ciphertext)
        data = json.loads(plaintext.decode())
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}
