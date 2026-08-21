"""Webhook token resolution: env -> OS credential store -> prompt."""

from __future__ import annotations

import keyring
import pytest
import typer

from exa.cli import simulate as sim


def test_env_var_wins(monkeypatch):
    monkeypatch.setenv("EXA_WEBHOOK_TOKEN", "env-tok")
    assert sim._resolve_token(tenant="sademodev22") == "env-tok"


def test_keyring_by_tenant(monkeypatch):
    monkeypatch.delenv("EXA_WEBHOOK_TOKEN", raising=False)
    store = {("exa-webhook", "sademodev22"): "kr-tok"}
    monkeypatch.setattr(keyring, "get_password", lambda s, u: store.get((s, u)))
    assert sim._resolve_token(tenant="sademodev22") == "kr-tok"


def test_keyring_default_user_fallback(monkeypatch):
    monkeypatch.delenv("EXA_WEBHOOK_TOKEN", raising=False)
    store = {("exa-webhook", "default"): "def-tok"}
    monkeypatch.setattr(keyring, "get_password", lambda s, u: store.get((s, u)))
    assert sim._resolve_token(tenant="no-entry-for-this") == "def-tok"


def test_no_prompt_errors_when_nothing_available(monkeypatch):
    monkeypatch.delenv("EXA_WEBHOOK_TOKEN", raising=False)
    monkeypatch.setattr(keyring, "get_password", lambda s, u: None)
    with pytest.raises(typer.Exit):
        sim._resolve_token(no_prompt=True, tenant="t")
