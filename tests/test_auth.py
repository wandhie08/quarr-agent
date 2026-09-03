"""Unit tests for Web API auth & RBAC (Phase 6 professional)."""

import time

import pytest

from quarr.api.auth import (
    TokenService, UserStore, LoginRateLimiter, build_user_store,
    hash_password, verify_password, AuthError, ROLES,
)


@pytest.mark.unit
def test_password_hash_roundtrip():
    h = hash_password("s3cr3t!")
    assert h != "s3cr3t!"
    assert verify_password("s3cr3t!", h)
    assert not verify_password("wrong", h)


@pytest.mark.unit
def test_user_store_verify():
    store = UserStore()
    store.add("alice", "pw123", role="operator")
    assert store.verify("alice", "pw123").role == "operator"
    assert store.verify("alice", "bad") is None
    assert store.verify("nobody", "pw123") is None


@pytest.mark.unit
def test_user_store_invalid_role():
    store = UserStore()
    with pytest.raises(AuthError):
        store.add("x", "y", role="superuser")


@pytest.mark.unit
def test_token_access_and_decode():
    ts = TokenService(secret="testsecret", access_ttl_min=30)
    tok = ts.access_token("alice", "admin")
    payload = ts.decode(tok, expected_type="access")
    assert payload["sub"] == "alice"
    assert payload["role"] == "admin"
    assert payload["type"] == "access"


@pytest.mark.unit
def test_token_wrong_type_rejected():
    ts = TokenService(secret="s")
    refresh = ts.refresh_token("bob", "viewer")
    with pytest.raises(AuthError):
        ts.decode(refresh, expected_type="access")


@pytest.mark.unit
def test_token_invalid_signature():
    ts1 = TokenService(secret="secret1")
    ts2 = TokenService(secret="secret2")
    tok = ts1.access_token("a", "admin")
    with pytest.raises(AuthError):
        ts2.decode(tok)


@pytest.mark.unit
def test_token_expired():
    ts = TokenService(secret="s", access_ttl_min=-1)  # already expired
    tok = ts.access_token("a", "viewer")
    with pytest.raises(AuthError):
        ts.decode(tok)


@pytest.mark.unit
def test_login_rate_limiter():
    clock = [0.0]
    rl = LoginRateLimiter(max_per_min=3, clock=lambda: clock[0])
    assert rl.check("ip1")
    assert rl.check("ip1")
    assert rl.check("ip1")
    assert not rl.check("ip1")  # 4th blocked
    # Different client unaffected.
    assert rl.check("ip2")
    # After the window, allowed again.
    clock[0] = 61.0
    assert rl.check("ip1")


@pytest.mark.unit
def test_build_user_store_seeds_admin():
    from quarr.core.config import Settings
    s = Settings(_env_file=None, web_admin_user="root", web_admin_password="secretpw")
    store = build_user_store(s)
    assert store.verify("root", "secretpw").role == "admin"


@pytest.mark.unit
def test_roles_constant():
    assert ROLES == ("viewer", "operator", "admin")
