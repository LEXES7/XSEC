"""Secure, cross-platform storage for AI provider API keys.

A key is resolved in this order, most explicit first:

1. The provider's environment variable - so CI/automation still works.
2. The OS secret store via the ``keyring`` library, which is encrypted at rest
   and uses the right native backend per platform:
     * macOS   -> Keychain
     * Windows -> Credential Manager (DPAPI)
     * Linux   -> Secret Service (GNOME Keyring / KWallet)
3. Nothing - the caller decides what to do (the AI engine just skips).

This means a key never has to live in a plaintext file, shell rc, or your
command history. ``keyring`` is an optional dependency; if it isn't installed
we fall back to the environment variable only.
"""

from __future__ import annotations

import os

SERVICE = "xsec"
DEFAULT_PROVIDER = "anthropic"

# provider -> (environment variable, keyring account name)
_PROVIDERS = {
    "anthropic": ("ANTHROPIC_API_KEY", "anthropic_api_key"),
    "groq": ("GROQ_API_KEY", "groq_api_key"),
    "openrouter": ("OPENROUTER_API_KEY", "openrouter_api_key"),
    "openai-compatible": ("OPENAI_API_KEY", "openai_compatible_api_key"),
}

# kept for backwards compatibility (older imports referenced these)
ACCOUNT = _PROVIDERS[DEFAULT_PROVIDER][1]
ENV_VAR = _PROVIDERS[DEFAULT_PROVIDER][0]


def _resolve(provider: str) -> tuple[str, str]:
    return _PROVIDERS.get(provider, _PROVIDERS[DEFAULT_PROVIDER])


def keyring_available() -> bool:
    try:
        import keyring  # noqa: F401
        return True
    except ImportError:
        return False


def get_api_key(provider: str = DEFAULT_PROVIDER) -> str | None:
    """Return the key from the environment, then the OS keyring, else None."""
    env_var, account = _resolve(provider)
    env = os.environ.get(env_var)
    if env:
        return env
    if keyring_available():
        try:
            import keyring
            return keyring.get_password(SERVICE, account)
        except Exception:
            # a locked/unavailable keyring backend shouldn't crash a scan
            return None
    return None


def set_api_key(value: str, provider: str = DEFAULT_PROVIDER) -> tuple[bool, str]:
    """Store the key in the OS keyring. Returns (ok, message)."""
    value = value.strip()
    if not value:
        return False, "Empty key, nothing stored."
    if not keyring_available():
        return False, (
            "keyring not installed. Install it with: pip install 'xsec[secure]'"
        )
    _, account = _resolve(provider)
    try:
        import keyring
        keyring.set_password(SERVICE, account, value)
    except Exception as exc:  # backend locked / unavailable
        return False, f"Could not store key in the OS keyring: {exc}"
    return True, f"{provider} API key stored securely in your OS keyring."


def clear_api_key(provider: str = DEFAULT_PROVIDER) -> tuple[bool, str]:
    """Delete the key from the OS keyring. Returns (ok, message)."""
    if not keyring_available():
        return False, "keyring not installed; nothing to clear."
    _, account = _resolve(provider)
    try:
        import keyring
        keyring.delete_password(SERVICE, account)
    except Exception:
        # delete_password raises if there's nothing stored; treat as a no-op
        return True, f"No stored {provider} key found (nothing to clear)."
    return True, f"Stored {provider} API key removed from your OS keyring."


def key_status(provider: str = DEFAULT_PROVIDER) -> str:
    """Human-readable summary of where the key would come from."""
    env_var, account = _resolve(provider)
    if os.environ.get(env_var):
        return f"[{provider}] Using key from ${env_var} (environment)."
    if keyring_available():
        try:
            import keyring
            if keyring.get_password(SERVICE, account):
                return f"[{provider}] Using key from the OS keyring (encrypted)."
        except Exception:
            pass
        return f"[{provider}] No key set. Store one with: xsec key set --provider {provider}"
    return (
        f"[{provider}] No key set, and keyring isn't installed. "
        f"Either set ${env_var} or run: pip install 'xsec[secure]'"
    )
