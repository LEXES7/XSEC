"""Tests for API-key resolution and the keyring helpers.

We use a fake in-memory keyring backend so nothing touches the real OS store.
"""

from __future__ import annotations

import pytest

import xsec.secrets as secrets


class _FakeKeyring:
    """Minimal stand-in for the keyring module's get/set/delete API."""

    def __init__(self):
        self.store: dict[tuple[str, str], str] = {}

    def get_password(self, service, account):
        return self.store.get((service, account))

    def set_password(self, service, account, value):
        self.store[(service, account)] = value

    def delete_password(self, service, account):
        if (service, account) not in self.store:
            raise KeyError("not found")
        del self.store[(service, account)]


@pytest.fixture
def fake_keyring(monkeypatch):
    fake = _FakeKeyring()
    monkeypatch.setattr(secrets, "keyring_available", lambda: True)
    # make `import keyring` inside the functions resolve to our fake
    import sys
    monkeypatch.setitem(sys.modules, "keyring", fake)
    return fake


def test_env_var_takes_priority(monkeypatch, fake_keyring):
    fake_keyring.set_password(secrets.SERVICE, secrets.ACCOUNT, "from-keyring")
    monkeypatch.setenv(secrets.ENV_VAR, "from-env")
    assert secrets.get_api_key() == "from-env"


def test_falls_back_to_keyring(monkeypatch, fake_keyring):
    monkeypatch.delenv(secrets.ENV_VAR, raising=False)
    fake_keyring.set_password(secrets.SERVICE, secrets.ACCOUNT, "from-keyring")
    assert secrets.get_api_key() == "from-keyring"


def test_none_when_nothing_set(monkeypatch, fake_keyring):
    monkeypatch.delenv(secrets.ENV_VAR, raising=False)
    assert secrets.get_api_key() is None


def test_set_and_clear_roundtrip(monkeypatch, fake_keyring):
    monkeypatch.delenv(secrets.ENV_VAR, raising=False)
    ok, _ = secrets.set_api_key("sk-ant-123")
    assert ok and secrets.get_api_key() == "sk-ant-123"
    ok, _ = secrets.clear_api_key()
    assert ok and secrets.get_api_key() is None


def test_set_empty_is_rejected(fake_keyring):
    ok, msg = secrets.set_api_key("   ")
    assert not ok and "Empty" in msg


def test_graceful_without_keyring(monkeypatch):
    monkeypatch.setattr(secrets, "keyring_available", lambda: False)
    monkeypatch.delenv(secrets.ENV_VAR, raising=False)
    assert secrets.get_api_key() is None
    ok, msg = secrets.set_api_key("sk-ant-123")
    assert not ok and "keyring" in msg.lower()


def test_status_strings(monkeypatch, fake_keyring):
    monkeypatch.setenv(secrets.ENV_VAR, "x")
    assert "environment" in secrets.key_status()
    monkeypatch.delenv(secrets.ENV_VAR, raising=False)
    fake_keyring.set_password(secrets.SERVICE, secrets.ACCOUNT, "x")
    assert "keyring" in secrets.key_status()


def test_providers_are_isolated(monkeypatch, fake_keyring):
    # a key stored for groq must not leak into anthropic and vice versa
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    secrets.set_api_key("groq-key", "groq")
    assert secrets.get_api_key("groq") == "groq-key"
    assert secrets.get_api_key("anthropic") is None


def test_provider_env_var(monkeypatch, fake_keyring):
    monkeypatch.setenv("GROQ_API_KEY", "from-env-groq")
    assert secrets.get_api_key("groq") == "from-env-groq"
