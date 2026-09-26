"""Auth middleware — token validation, JIT user provisioning, role gates.

Token-validation tests use a real RS256 keypair generated per-module so
the middleware actually exercises PyJWT end-to-end (signing, JWKS
lookup, claim extraction), plus hand-forged tokens for the
algorithm-confusion cases.

Database tests use the in-memory SQLite harness consistent with
``tests/test_models/`` — JIT row creation, role refresh on existing
rows, and the ``disabled_at`` kill switch all flow through real ORM
operations.
"""

from __future__ import annotations

import time
import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, patch

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException
from jwt.algorithms import RSAAlgorithm
from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from darla.auth.middleware import _map_role, current_user, require_role
from darla.config import get_settings
from darla.models import Base, User, UserRole

# ---------------------------------------------------------------------------
# Pure-Python role mapper
# ---------------------------------------------------------------------------


class TestRoleMapper:
    def test_no_roles_returns_none(self) -> None:
        # No assignment → 403.  RFC §3 decision #6.
        assert _map_role([], "Darla.Viewer", "Darla.Analyst") is None

    def test_viewer_only(self) -> None:
        assert _map_role(
            ["Darla.Viewer"], "Darla.Viewer", "Darla.Analyst",
        ) is UserRole.VIEWER

    def test_analyst_only(self) -> None:
        assert _map_role(
            ["Darla.Analyst"], "Darla.Viewer", "Darla.Analyst",
        ) is UserRole.ANALYST

    def test_both_picks_analyst(self) -> None:
        # Higher-tier wins — you can't be "less than" an analyst once
        # the IdP has granted it.
        assert _map_role(
            ["Darla.Viewer", "Darla.Analyst"],
            "Darla.Viewer", "Darla.Analyst",
        ) is UserRole.ANALYST

    def test_unrelated_role_ignored(self) -> None:
        # A role assignment unrelated to Darla (e.g. "Office365.User")
        # doesn't grant anything.
        assert _map_role(
            ["Office365.User"], "Darla.Viewer", "Darla.Analyst",
        ) is None

    def test_case_sensitive(self) -> None:
        # If operator's IdP uses lowercase values, they configure the
        # env vars to match — middleware must NOT silently lowercase.
        assert _map_role(
            ["darla.analyst"], "Darla.Viewer", "Darla.Analyst",
        ) is None


# ---------------------------------------------------------------------------
# RS256 keypair + JWT helpers
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def rsa_keypair():
    """Generate a fresh RSA-2048 keypair for the test module.

    Yields ``(private_pem_bytes, jwk_public)`` where ``jwk_public`` is
    the cryptography-derived JWK we'll feed into the JWKS cache.
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Derive a JWK from the public key — PyJWT's RSAAlgorithm handles
    # the n/e base64url encoding.  No ``alg`` member, matching Entra's
    # published JWKS.
    jwk_public = RSAAlgorithm.to_jwk(private_key.public_key(), as_dict=True)
    jwk_public["kid"] = "test-key-1"
    return private_pem, jwk_public


def _make_token(
    private_pem: bytes,
    *,
    issuer: str,
    audience: str,
    claims: dict[str, Any] | None = None,
    expires_in_seconds: int = 3600,
    kid: str = "test-key-1",
) -> str:
    """Mint a signed RS256 JWT for tests."""
    now = int(time.time())
    payload: dict[str, Any] = {
        "iss": issuer,
        "aud": audience,
        "iat": now,
        "exp": now + expires_in_seconds,
        "sub": "test-subject",
        "preferred_username": "alice@example.com",
        "name": "Alice",
        "roles": ["Darla.Analyst"],
    }
    if claims:
        payload.update(claims)
    return jwt.encode(
        payload, private_pem, algorithm="RS256",
        headers={"kid": kid},
    )


# ---------------------------------------------------------------------------
# Async DB harness — in-memory SQLite via the async sqlalchemy driver
# ---------------------------------------------------------------------------


@pytest.fixture
async def async_db():
    """Async SQLite session with the User table pre-created."""
    # `aiosqlite` is required for async SQLite; if missing, skip these tests.
    pytest.importorskip("aiosqlite")
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:", echo=False,
    )
    sync_engine = create_engine("sqlite:///:memory:")
    # Use the async engine for the actual session, but create_all needs
    # to run via the async machinery so the table exists in the DB the
    # session sees.
    async with engine.begin() as conn:
        await conn.run_sync(
            Base.metadata.create_all,
            tables=[User.__table__],
        )
    session = AsyncSession(engine, expire_on_commit=False)
    try:
        yield session
    finally:
        await session.close()
        await engine.dispose()
        sync_engine.dispose()


@pytest.fixture
def auth_settings(monkeypatch, rsa_keypair):
    """Configure settings for a working OIDC validation flow."""
    s = get_settings()
    monkeypatch.setattr(s, "auth_enabled", True)
    monkeypatch.setattr(s, "oidc_issuer", "https://issuer.example.com")
    monkeypatch.setattr(s, "oidc_audience", "test-audience")
    monkeypatch.setattr(s, "oidc_jwks_url", "https://issuer.example.com/keys")
    monkeypatch.setattr(s, "oidc_subject_claim", "sub")
    monkeypatch.setattr(s, "oidc_role_claim", "roles")
    monkeypatch.setattr(s, "oidc_viewer_role_value", "Darla.Viewer")
    monkeypatch.setattr(s, "oidc_analyst_role_value", "Darla.Analyst")
    monkeypatch.setattr(s, "oidc_allowed_algorithms", ["RS256"])
    return s


@pytest.fixture
def disabled_settings(monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "auth_enabled", False)
    return s


@pytest.fixture
def patched_jwks(rsa_keypair):
    """Stub the JWKS lookup to return our test public key."""
    _, jwk_public = rsa_keypair
    with patch(
        "darla.auth.middleware.get_signing_key", AsyncMock(return_value=jwk_public),
    ) as p:
        yield p


def _make_request(token: str | None = None):
    """Build a minimal Starlette Request mock for the middleware."""
    from starlette.requests import Request

    headers = []
    if token is not None:
        headers.append((b"authorization", f"Bearer {token}".encode()))
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/v1/kits",
        "headers": headers,
        "client": ("127.0.0.1", 12345),
        "query_string": b"",
    }
    return Request(scope)


# ---------------------------------------------------------------------------
# Disabled mode
# ---------------------------------------------------------------------------


class TestDisabledMode:
    @pytest.mark.asyncio
    async def test_returns_none_no_token_required(
        self, disabled_settings, async_db,
    ) -> None:
        # Disabled mode: no token, no user, no error.  request.state
        # gets ``auth_mode='disabled'`` for the audit middleware.
        req = _make_request(token=None)
        result = await current_user(req, async_db)
        assert result is None
        assert req.state.auth_mode == "disabled"
        assert req.state.actor_subject is None

    @pytest.mark.asyncio
    async def test_require_role_no_op_in_disabled_mode(
        self, disabled_settings, async_db,
    ) -> None:
        # require_role(ANALYST) with auth disabled returns None — the
        # safety here is the localhost-only bind enforced by guardrails.
        dep = require_role(UserRole.ANALYST)
        # Manually invoke the inner dependency with a None user
        # (simulating Depends(current_user) → None)
        result = await dep(user=None)
        assert result is None


# ---------------------------------------------------------------------------
# Auth-enabled — happy paths
# ---------------------------------------------------------------------------


class TestValidToken:
    @pytest.mark.asyncio
    async def test_valid_token_creates_user_jit(
        self, auth_settings, rsa_keypair, patched_jwks, async_db,
    ) -> None:
        private_pem, _ = rsa_keypair
        token = _make_token(
            private_pem,
            issuer=auth_settings.oidc_issuer,
            audience=auth_settings.oidc_audience,
        )
        req = _make_request(token)
        user = await current_user(req, async_db)

        assert user is not None
        assert user.oidc_subject == "test-subject"
        assert user.upn == "alice@example.com"
        assert user.role is UserRole.ANALYST
        assert user.disabled_at is None
        # request.state populated for Phase 5 audit middleware
        assert req.state.auth_mode == "oidc"
        assert req.state.actor_subject == "test-subject"

    @pytest.mark.asyncio
    async def test_second_login_refreshes_existing_user(
        self, auth_settings, rsa_keypair, patched_jwks, async_db,
    ) -> None:
        # First login creates the row.  Second login (different display
        # name, different role) updates it in place.
        private_pem, _ = rsa_keypair
        token1 = _make_token(
            private_pem,
            issuer=auth_settings.oidc_issuer,
            audience=auth_settings.oidc_audience,
            claims={"name": "Alice Original", "roles": ["Darla.Viewer"]},
        )
        await current_user(_make_request(token1), async_db)

        token2 = _make_token(
            private_pem,
            issuer=auth_settings.oidc_issuer,
            audience=auth_settings.oidc_audience,
            claims={"name": "Alice Renamed", "roles": ["Darla.Analyst"]},
        )
        user2 = await current_user(_make_request(token2), async_db)

        assert user2.display_name == "Alice Renamed"
        assert user2.role is UserRole.ANALYST  # promoted from VIEWER

        # Verify only one row exists — JIT must not duplicate.
        from sqlalchemy import select

        rows = (await async_db.scalars(select(User))).all()
        assert len(rows) == 1


# ---------------------------------------------------------------------------
# Auth-enabled — rejection paths
# ---------------------------------------------------------------------------


class TestRejections:
    @pytest.mark.asyncio
    async def test_missing_bearer_returns_401(
        self, auth_settings, async_db,
    ) -> None:
        with pytest.raises(HTTPException) as exc:
            await current_user(_make_request(token=None), async_db)
        assert exc.value.status_code == 401

    @pytest.mark.asyncio
    async def test_malformed_token_returns_401(
        self, auth_settings, async_db,
    ) -> None:
        with pytest.raises(HTTPException) as exc:
            await current_user(_make_request("not-a-jwt"), async_db)
        assert exc.value.status_code == 401

    @pytest.mark.asyncio
    async def test_expired_token_returns_401(
        self, auth_settings, rsa_keypair, patched_jwks, async_db,
    ) -> None:
        private_pem, _ = rsa_keypair
        # exp in the past
        token = _make_token(
            private_pem,
            issuer=auth_settings.oidc_issuer,
            audience=auth_settings.oidc_audience,
            expires_in_seconds=-100,
        )
        with pytest.raises(HTTPException) as exc:
            await current_user(_make_request(token), async_db)
        assert exc.value.status_code == 401

    @pytest.mark.asyncio
    async def test_wrong_audience_returns_401(
        self, auth_settings, rsa_keypair, patched_jwks, async_db,
    ) -> None:
        private_pem, _ = rsa_keypair
        token = _make_token(
            private_pem,
            issuer=auth_settings.oidc_issuer,
            audience="some-other-app",  # not our API
        )
        with pytest.raises(HTTPException) as exc:
            await current_user(_make_request(token), async_db)
        assert exc.value.status_code == 401

    @pytest.mark.asyncio
    async def test_wrong_issuer_returns_401(
        self, auth_settings, rsa_keypair, patched_jwks, async_db,
    ) -> None:
        private_pem, _ = rsa_keypair
        token = _make_token(
            private_pem,
            issuer="https://attacker.example.com",
            audience=auth_settings.oidc_audience,
        )
        with pytest.raises(HTTPException) as exc:
            await current_user(_make_request(token), async_db)
        assert exc.value.status_code == 401

    @pytest.mark.asyncio
    async def test_no_role_claim_returns_403(
        self, auth_settings, rsa_keypair, patched_jwks, async_db,
    ) -> None:
        # Authenticated but unauthorized — RFC §3 decision #6.
        private_pem, _ = rsa_keypair
        token = _make_token(
            private_pem,
            issuer=auth_settings.oidc_issuer,
            audience=auth_settings.oidc_audience,
            claims={"roles": []},
        )
        with pytest.raises(HTTPException) as exc:
            await current_user(_make_request(token), async_db)
        assert exc.value.status_code == 403
        assert "role" in exc.value.detail.lower()

    @pytest.mark.asyncio
    async def test_disabled_user_returns_403(
        self, auth_settings, rsa_keypair, patched_jwks, async_db,
    ) -> None:
        # Local kill switch beats valid token + valid role.
        async_db.add(User(
            oidc_subject="test-subject",
            upn="alice@example.com",
            display_name="Alice",
            role=UserRole.ANALYST,
            last_login_at=datetime.now(UTC),
            disabled_at=datetime.now(UTC),
        ))
        await async_db.commit()

        private_pem, _ = rsa_keypair
        token = _make_token(
            private_pem,
            issuer=auth_settings.oidc_issuer,
            audience=auth_settings.oidc_audience,
        )
        with pytest.raises(HTTPException) as exc:
            await current_user(_make_request(token), async_db)
        assert exc.value.status_code == 403
        assert "disabled" in exc.value.detail.lower()


# ---------------------------------------------------------------------------
# require_role enforcement
# ---------------------------------------------------------------------------


class TestRequireRole:
    @pytest.mark.asyncio
    async def test_viewer_blocked_from_analyst_route(
        self, auth_settings,
    ) -> None:
        # Pure dep test — pass a viewer-roled User in directly.
        user = User(
            id=uuid.uuid4(),
            oidc_subject="x", upn="x@example.com", display_name="X",
            role=UserRole.VIEWER,
            last_login_at=datetime.now(UTC),
        )
        dep = require_role(UserRole.ANALYST)
        with pytest.raises(HTTPException) as exc:
            await dep(user=user)
        assert exc.value.status_code == 403

    @pytest.mark.asyncio
    async def test_analyst_passes_analyst_route(self, auth_settings) -> None:
        user = User(
            id=uuid.uuid4(),
            oidc_subject="x", upn="x@example.com", display_name="X",
            role=UserRole.ANALYST,
            last_login_at=datetime.now(UTC),
        )
        dep = require_role(UserRole.ANALYST)
        got = await dep(user=user)
        assert got is user

    @pytest.mark.asyncio
    async def test_role_override_wins_in_gate(self, auth_settings) -> None:
        # Token-derived ANALYST + CLI-set VIEWER override → blocked
        # from analyst routes.  This is the whole point of the
        # override — IdP propagation lag protection.
        user = User(
            id=uuid.uuid4(),
            oidc_subject="x", upn="x@example.com", display_name="X",
            role=UserRole.ANALYST,
            role_override=UserRole.VIEWER,
            last_login_at=datetime.now(UTC),
        )
        dep = require_role(UserRole.ANALYST)
        with pytest.raises(HTTPException) as exc:
            await dep(user=user)
        assert exc.value.status_code == 403


# ---------------------------------------------------------------------------
# Disabled-mode CRITICAL log middleware
# ---------------------------------------------------------------------------


class TestDisabledAuthLoggingMiddleware:
    @pytest.mark.asyncio
    async def test_logs_critical_when_auth_disabled(
        self, disabled_settings, caplog,
    ) -> None:
        from darla.auth.middleware import DisabledAuthLoggingMiddleware

        # Build the middleware around a stub app that returns "ok"
        async def app(scope, receive, send):
            ...

        mw = DisabledAuthLoggingMiddleware(app)

        async def call_next(request):
            from starlette.responses import Response

            return Response("ok")

        with caplog.at_level("CRITICAL", logger="darla.auth.middleware"):
            await mw.dispatch(_make_request(token=None), call_next)

        # Single CRITICAL line containing the alert-keyword string.
        assert any(
            "AUTH DISABLED" in r.message and r.levelname == "CRITICAL"
            for r in caplog.records
        )

    @pytest.mark.asyncio
    async def test_silent_when_auth_enabled(
        self, auth_settings, caplog,
    ) -> None:
        from darla.auth.middleware import DisabledAuthLoggingMiddleware

        async def app(scope, receive, send):
            ...

        mw = DisabledAuthLoggingMiddleware(app)

        async def call_next(request):
            from starlette.responses import Response

            return Response("ok")

        with caplog.at_level("CRITICAL", logger="darla.auth.middleware"):
            await mw.dispatch(_make_request(token=None), call_next)

        # No CRITICAL lines from this module — middleware must be inert
        # when auth is on.
        assert not any(
            r.levelname == "CRITICAL"
            and r.name == "darla.auth.middleware"
            for r in caplog.records
        )


# ---------------------------------------------------------------------------
# Algorithm confusion — the header's ``alg`` is attacker-controlled
# ---------------------------------------------------------------------------


def _b64url(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _forge(alg: str, secret: bytes, *, issuer: str, audience: str) -> str:
    """Hand-build a token with an arbitrary header ``alg``.

    Library encoders refuse to HMAC-sign with an asymmetric public key
    (that refusal is exactly the defense), so build the JWS by hand the
    way an attacker would.
    """
    import hashlib
    import hmac
    import json

    header = {"alg": alg, "kid": "test-key-1", "typ": "JWT"}
    now = int(time.time())
    payload = {
        "iss": issuer, "aud": audience, "iat": now, "exp": now + 600,
        "sub": "attacker", "roles": ["Darla.Analyst"],
    }
    signing_input = (
        f"{_b64url(json.dumps(header).encode())}."
        f"{_b64url(json.dumps(payload).encode())}"
    )
    if alg == "none":
        signature = b""
    elif not alg.startswith("HS"):
        signature = b"\x00" * 64  # shape only; never verifies
    else:
        digest = {"HS256": hashlib.sha256, "HS384": hashlib.sha384,
                  "HS512": hashlib.sha512}[alg]
        signature = hmac.new(secret, signing_input.encode(), digest).digest()
    return f"{signing_input}.{_b64url(signature)}"


class TestAlgorithmConfusion:
    """Every forged or off-allowlist token must end in a 401 — never a
    500 (python-jose raised JWKError outside its JWTError tree, so these
    used to escape the handler) and never a validated user."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("alg", ["HS256", "HS384", "HS512", "none"])
    @pytest.mark.parametrize("secret_kind", ["jwk_json", "modulus"])
    async def test_forged_symmetric_or_none_token_rejected(
        self, alg, secret_kind, auth_settings, rsa_keypair, patched_jwks,
        async_db,
    ) -> None:
        import json

        _, jwk_public = rsa_keypair
        secret = (
            json.dumps(jwk_public).encode() if secret_kind == "jwk_json"
            else jwk_public["n"].encode()
        )
        token = _forge(
            alg, secret,
            issuer=auth_settings.oidc_issuer,
            audience=auth_settings.oidc_audience,
        )
        with pytest.raises(HTTPException) as exc:
            await current_user(_make_request(token), async_db)
        assert exc.value.status_code == 401
        assert "not allowed" in exc.value.detail
        # Rejected before the key was even fetched.
        patched_jwks.assert_not_called()

    @pytest.mark.asyncio
    async def test_validly_signed_but_off_allowlist_alg_rejected(
        self, auth_settings, rsa_keypair, patched_jwks, async_db,
    ) -> None:
        # Genuine IdP key, genuine signature — but RS512 isn't allowlisted.
        private_pem, _ = rsa_keypair
        now = int(time.time())
        token = jwt.encode(
            {"iss": auth_settings.oidc_issuer,
             "aud": auth_settings.oidc_audience,
             "exp": now + 600, "sub": "s", "roles": ["Darla.Analyst"]},
            private_pem, algorithm="RS512", headers={"kid": "test-key-1"},
        )
        with pytest.raises(HTTPException) as exc:
            await current_user(_make_request(token), async_db)
        assert exc.value.status_code == 401

    @pytest.mark.asyncio
    async def test_key_type_mismatch_is_401_not_500(
        self, auth_settings, monkeypatch, rsa_keypair, patched_jwks,
        async_db,
    ) -> None:
        # Operator allowlists ES256 but the IdP key is RSA — building the
        # key must fail inside the PyJWTError handler.
        monkeypatch.setattr(auth_settings, "oidc_allowed_algorithms",
                            ["RS256", "ES256"])
        token = _forge(
            "ES256", b"",
            issuer=auth_settings.oidc_issuer,
            audience=auth_settings.oidc_audience,
        )
        with pytest.raises(HTTPException) as exc:
            await current_user(_make_request(token), async_db)
        assert exc.value.status_code == 401
        assert exc.value.detail.startswith("Invalid token")

    @pytest.mark.asyncio
    async def test_jwk_pinned_alg_must_match_header(
        self, auth_settings, monkeypatch, rsa_keypair, async_db,
    ) -> None:
        private_pem, jwk_public = rsa_keypair
        monkeypatch.setattr(auth_settings, "oidc_allowed_algorithms",
                            ["RS256", "PS256"])
        pinned = {**jwk_public, "alg": "RS256"}
        now = int(time.time())
        token = jwt.encode(
            {"iss": auth_settings.oidc_issuer,
             "aud": auth_settings.oidc_audience,
             "exp": now + 600, "sub": "s", "roles": ["Darla.Analyst"]},
            private_pem, algorithm="PS256", headers={"kid": "test-key-1"},
        )
        with (
            patch("darla.auth.middleware.get_signing_key",
                  AsyncMock(return_value=pinned)),
            pytest.raises(HTTPException) as exc,
        ):
            await current_user(_make_request(token), async_db)
        assert exc.value.status_code == 401
        assert "does not match signing key" in exc.value.detail

    @pytest.mark.asyncio
    async def test_token_without_exp_rejected(
        self, auth_settings, rsa_keypair, patched_jwks, async_db,
    ) -> None:
        private_pem, _ = rsa_keypair
        token = jwt.encode(
            {"iss": auth_settings.oidc_issuer,
             "aud": auth_settings.oidc_audience,
             "sub": "s", "roles": ["Darla.Analyst"]},
            private_pem, algorithm="RS256", headers={"kid": "test-key-1"},
        )
        with pytest.raises(HTTPException) as exc:
            await current_user(_make_request(token), async_db)
        assert exc.value.status_code == 401
