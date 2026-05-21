from __future__ import annotations

"""
Thin wrapper around the `keyring` library for OS-native credential storage.
macOS: Keychain, Windows: Credential Manager, Linux: libsecret / kwallet.

All functions are no-ops (returning None / False) when keyring is not installed.
"""

from typing import List, Optional

_SERVICE = "aitrace-cli"


def _keyring():
    """Lazy import — returns the keyring module or None."""
    try:
        import keyring as _kr
        return _kr
    except ImportError:
        return None


def write_key(provider: str, api_key: str) -> bool:
    """
    Store *api_key* in the OS keychain under *provider*.
    Returns True on success, False if keyring is unavailable or write fails.
    """
    kr = _keyring()
    if kr is None:
        return False
    try:
        kr.set_password(_SERVICE, provider, api_key)
        return True
    except Exception:
        return False


def read_key(provider: str) -> Optional[str]:
    """
    Retrieve the stored key for *provider* from the OS keychain.
    Returns None if not found or keyring unavailable.
    """
    kr = _keyring()
    if kr is None:
        return None
    try:
        return kr.get_password(_SERVICE, provider)
    except Exception:
        return None


def delete_key(provider: str) -> bool:
    """
    Delete the stored key for *provider* from the OS keychain.
    Returns True on success, False otherwise.
    """
    kr = _keyring()
    if kr is None:
        return False
    try:
        kr.delete_password(_SERVICE, provider)
        return True
    except Exception:
        return False


def list_stored() -> List[str]:
    """
    Return a list of provider names that have keys stored in the keychain.
    Not all keyring backends support enumeration; returns [] on unsupported backends.
    """
    kr = _keyring()
    if kr is None:
        return []
    try:
        # keyring.get_keyring() may expose a get_credential API on some backends
        backend = kr.get_keyring()
        if hasattr(backend, "get_credential"):
            # We can't enumerate without knowing names; return empty list
            return []
        return []
    except Exception:
        return []


def is_available() -> bool:
    """Return True if keyring is installed and a functional backend is available."""
    kr = _keyring()
    if kr is None:
        return False
    try:
        backend = kr.get_keyring()
        # Fail-safe backend indicates no real keychain
        return "fail" not in type(backend).__name__.lower()
    except Exception:
        return False
