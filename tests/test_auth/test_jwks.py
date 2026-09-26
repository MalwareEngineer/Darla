"""JWKS cache + OIDC discovery — covers the rotation-resilience contract.

The cache must:

* Cold-start via OIDC discovery when ``PK_OIDC_JWKS_URL`` is empty.
* Skip discovery when ``PK_OIDC_JWKS_URL`` is pinned.
* Refresh on cache TTL expiry.
* Force-refresh on ``kid`` miss (legitimate IdP key rotation).
* Surface clear errors when the IdP is unreachable, the discovery doc
  is malformed, or the JWKS is empty.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from darla.auth.jwks import JWKSError, _reset_cache_for_tests, get_signing_key


@pytest.fixture(autouse=True)
def _reset_jwks_cache():
    """Each test starts with an empty JWKS cache — module-level state
    bleeds across tests otherwise and produces flaky results."""
    _reset_cache_for_tests()
    yield
    _reset_cache_for_tests()


@pytest.fixture
def settings_via_discovery(monkeypatch):
    """Settings shape that goes through OIDC discovery (no pinned JWKS)."""
    from darla.config import get_settings

    s = get_settings()
    monkeypatch.setattr(s, "oidc_issuer", "https://issuer.example.com")
    monkeypatch.setattr(s, "oidc_jwks_url", "")
    monkeypatch.setattr(s, "oidc_jwks_cache_ttl", 3600)
    return s


@pytest.fixture
def settings_pinned_jwks(monkeypatch):
    """Settings shape that skips discovery — JWKS URL pinned directly."""
    from darla.config import get_settings

    s = get_settings()
    monkeypatch.setattr(s, "oidc_issuer", "")
    monkeypatch.setattr(
        s, "oidc_jwks_url", "https://issuer.example.com/.well-known/jwks.json",
    )
    monkeypatch.setattr(s, "oidc_jwks_cache_ttl", 3600)
    return s


def _httpx_response(json_body: dict | None = None, status: int = 200) -> MagicMock:
    """Build a MagicMock that quacks like httpx.Response just enough."""
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status
    resp.json.return_value = json_body or {}
    if 200 <= status < 300:
        resp.raise_for_status = MagicMock(return_value=None)
    else:
        resp.raise_for_status = MagicMock(
            side_effect=httpx.HTTPStatusError(
                f"HTTP {status}", request=MagicMock(), response=resp,
            ),
        )
    return resp


def _patch_httpx_get(side_effect_or_responses):
    """Patch httpx.AsyncClient.get with a list of responses or a side_effect.

    Sequenced lists let us simulate "first call returns discovery,
    second returns JWKS" deterministically.
    """
    if isinstance(side_effect_or_responses, list):
        mock = AsyncMock(side_effect=side_effect_or_responses)
    else:
        mock = AsyncMock(side_effect=side_effect_or_responses)
    return patch.object(httpx.AsyncClient, "get", mock)


# ---------------------------------------------------------------------------
# Cold-start cache fill
# ---------------------------------------------------------------------------


class TestColdStart:
    @pytest.mark.asyncio
    async def test_discovery_then_jwks_fetch(self, settings_via_discovery) -> None:
        # Two-call sequence: GET discovery doc, then GET jwks_uri.
        # Verify both calls are made and the right key is cached.
        responses = [
            _httpx_response({
                "jwks_uri": "https://issuer.example.com/keys",
                "issuer": "https://issuer.example.com",
            }),
            _httpx_response({"keys": [
                {"kid": "key-1", "kty": "RSA", "n": "abc", "e": "AQAB"},
            ]}),
        ]
        with _patch_httpx_get(responses):
            key = await get_signing_key("key-1")
        assert key["kid"] == "key-1"

    @pytest.mark.asyncio
    async def test_pinned_jwks_url_skips_discovery(self, settings_pinned_jwks) -> None:
        # When operator pins JWKS URL, only one HTTP call.
        responses = [
            _httpx_response({"keys": [
                {"kid": "key-1", "kty": "RSA", "n": "abc", "e": "AQAB"},
            ]}),
        ]
        with _patch_httpx_get(responses) as patched:
            await get_signing_key("key-1")
        assert patched.call_count == 1

    @pytest.mark.asyncio
    async def test_empty_issuer_with_no_pin_raises(self, monkeypatch) -> None:
        from darla.config import get_settings

        s = get_settings()
        monkeypatch.setattr(s, "oidc_issuer", "")
        monkeypatch.setattr(s, "oidc_jwks_url", "")

        with pytest.raises(JWKSError, match="PK_OIDC_ISSUER is empty"):
            await get_signing_key("any-kid")


# ---------------------------------------------------------------------------
# Error surfaces
# ---------------------------------------------------------------------------


class TestErrorSurfaces:
    @pytest.mark.asyncio
    async def test_discovery_http_error_wraps(self, settings_via_discovery) -> None:
        with (
            _patch_httpx_get(httpx.ConnectError("idp down")),
            pytest.raises(JWKSError, match="OIDC discovery failed"),
        ):
            await get_signing_key("key-1")

    @pytest.mark.asyncio
    async def test_discovery_missing_jwks_uri_raises(self, settings_via_discovery) -> None:
        # A discovery doc without jwks_uri is malformed — give the
        # operator a clear error rather than a confusing AttributeError.
        responses = [_httpx_response({"issuer": "https://issuer.example.com"})]
        with (
            _patch_httpx_get(responses),
            pytest.raises(JWKSError, match="missing jwks_uri"),
        ):
            await get_signing_key("key-1")

    @pytest.mark.asyncio
    async def test_jwks_fetch_http_error_wraps(self, settings_pinned_jwks) -> None:
        with (
            _patch_httpx_get(httpx.ConnectError("jwks down")),
            pytest.raises(JWKSError, match="JWKS fetch failed"),
        ):
            await get_signing_key("key-1")

    @pytest.mark.asyncio
    async def test_empty_keys_array_raises(self, settings_pinned_jwks) -> None:
        responses = [_httpx_response({"keys": []})]
        with _patch_httpx_get(responses), pytest.raises(JWKSError, match="no keys"):
            await get_signing_key("key-1")

    @pytest.mark.asyncio
    async def test_keys_without_kid_filtered(self, settings_pinned_jwks) -> None:
        # Keys without ``kid`` can't be matched against a JWT header
        # — they're not "usable", so the cache treats them as absent.
        responses = [_httpx_response({"keys": [
            {"kty": "RSA", "n": "abc"},  # no kid
        ]})]
        with (
            _patch_httpx_get(responses),
            pytest.raises(JWKSError, match="no usable kid-keyed keys"),
        ):
            await get_signing_key("key-1")


# ---------------------------------------------------------------------------
# Rotation resilience
# ---------------------------------------------------------------------------


class TestRotationResilience:
    @pytest.mark.asyncio
    async def test_kid_miss_forces_refetch(self, settings_pinned_jwks) -> None:
        # Cold-start fetches old key.  Token comes in signed with
        # a NEW key (kid the cache doesn't know).  Must trigger a
        # forced refresh and find the new key.
        first_jwks = _httpx_response({"keys": [
            {"kid": "old-key", "kty": "RSA", "n": "abc", "e": "AQAB"},
        ]})
        rotated_jwks = _httpx_response({"keys": [
            {"kid": "old-key", "kty": "RSA", "n": "abc", "e": "AQAB"},
            {"kid": "new-key", "kty": "RSA", "n": "def", "e": "AQAB"},
        ]})

        with _patch_httpx_get([first_jwks]):
            await get_signing_key("old-key")

        with _patch_httpx_get([rotated_jwks]) as patched_after:
            key = await get_signing_key("new-key")
        assert key["kid"] == "new-key"
        # The kid-miss path should have triggered exactly one refresh.
        assert patched_after.call_count == 1

    @pytest.mark.asyncio
    async def test_unknown_kid_after_refresh_raises(self, settings_pinned_jwks) -> None:
        # Forged token (kid the IdP has never published) — refresh
        # once, still not found, raise.
        responses = [
            _httpx_response({"keys": [
                {"kid": "real-key", "kty": "RSA", "n": "abc", "e": "AQAB"},
            ]}),
        ]
        with (
            _patch_httpx_get(responses),
            pytest.raises(JWKSError, match="not found in JWKS"),
        ):
            await get_signing_key("forged-key")
