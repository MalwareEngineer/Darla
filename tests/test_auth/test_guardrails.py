"""Startup guardrails (RFC §16) — verify each refusal path.

The guardrail set is the difference between "auth-disabled is a
foot-gun" and "auth-disabled is a deliberate choice that requires
acknowledgement."  Every refusal path here is load-bearing: removing
any one of these tests would re-open a misconfiguration vector.
"""

from __future__ import annotations

from unittest.mock import patch

import httpx
import pytest

from darla.auth.guardrails import (
    AUTH_OFF_ACK,
    _imds_is_reachable,
    run_startup_guardrails,
)
from darla.config import Settings


def _make_settings(**overrides) -> Settings:
    """Build a Settings object with disabled-mode-passing defaults.

    Each test then breaks one specific invariant via overrides.
    """
    defaults = dict(
        debug=True,
        auth_enabled=False,
        i_understand_auth_is_off=AUTH_OFF_ACK,
        bind_address="127.0.0.1",
    )
    defaults.update(overrides)
    return Settings(**defaults)


# ---------------------------------------------------------------------------
# Disabled-mode happy path — all guardrails pass
# ---------------------------------------------------------------------------


class TestDisabledModeHappyPath:
    def test_localhost_dev_starts_clean(self) -> None:
        # Community quickstart: ack set, localhost bind, debug on,
        # not on AWS.  Must not raise.
        with patch("darla.auth.guardrails._imds_is_reachable", return_value=False):
            run_startup_guardrails(_make_settings())

    def test_localhost_alias_accepted(self) -> None:
        # ``localhost`` literal is also acceptable — same security
        # property as 127.0.0.1, just different DNS.
        with patch("darla.auth.guardrails._imds_is_reachable", return_value=False):
            run_startup_guardrails(_make_settings(bind_address="localhost"))


# ---------------------------------------------------------------------------
# Disabled-mode refusals
# ---------------------------------------------------------------------------


class TestAckTokenRequired:
    def test_missing_ack_refuses(self) -> None:
        # The whole point of the verbose ack string is that an empty
        # value (or any other) means "did not affirmatively choose
        # to disable auth."
        with patch("darla.auth.guardrails._imds_is_reachable", return_value=False):
            with pytest.raises(SystemExit) as exc:
                run_startup_guardrails(_make_settings(i_understand_auth_is_off=""))
            assert "PK_I_UNDERSTAND_AUTH_IS_OFF" in str(exc.value)

    def test_wrong_ack_refuses(self) -> None:
        with patch("darla.auth.guardrails._imds_is_reachable", return_value=False):
            with pytest.raises(SystemExit) as exc:
                run_startup_guardrails(
                    _make_settings(i_understand_auth_is_off="yes"),
                )
            assert "PK_I_UNDERSTAND_AUTH_IS_OFF" in str(exc.value)


class TestLocalhostBindRequired:
    @pytest.mark.parametrize("bad_bind", [
        "0.0.0.0",        # the prod default — most common foot-gun
        "10.0.0.1",       # internal network
        "192.168.1.5",    # LAN
        "::",             # IPv6 wildcard
        "*",              # some uvicorn configs use this
    ])
    def test_non_localhost_bind_refuses(self, bad_bind: str) -> None:
        with patch("darla.auth.guardrails._imds_is_reachable", return_value=False):
            with pytest.raises(SystemExit) as exc:
                run_startup_guardrails(_make_settings(bind_address=bad_bind))
            assert "PK_BIND_ADDRESS" in str(exc.value)


class TestDebugModeRequired:
    def test_debug_off_refuses(self) -> None:
        # Production-shaped settings (debug off) must not skip auth —
        # this catches the "copy-pasted prod env to dev" mistake.
        with patch("darla.auth.guardrails._imds_is_reachable", return_value=False):
            with pytest.raises(SystemExit) as exc:
                run_startup_guardrails(_make_settings(debug=False))
            assert "PK_DEBUG" in str(exc.value)


class TestImdsRefusal:
    def test_imds_reachable_refuses(self) -> None:
        # Detected on AWS — refuse to start in disabled mode.
        with patch("darla.auth.guardrails._imds_is_reachable", return_value=True):
            with pytest.raises(SystemExit) as exc:
                run_startup_guardrails(_make_settings())
            assert "IMDS" in str(exc.value)


# ---------------------------------------------------------------------------
# IMDS detection itself
# ---------------------------------------------------------------------------


class TestImdsDetection:
    def test_200_response_means_on_aws(self) -> None:
        # IMDSv1 returns 200 on the listing endpoint.
        mock_response = httpx.Response(200, text="ami-id\n")
        with patch.object(httpx.Client, "get", return_value=mock_response):
            assert _imds_is_reachable() is True

    def test_401_challenge_also_means_on_aws(self) -> None:
        # IMDSv2 requires a token-fetch step → 401 on direct GET.
        # Still tells us we're on AWS.
        mock_response = httpx.Response(401, text="missing token")
        with patch.object(httpx.Client, "get", return_value=mock_response):
            assert _imds_is_reachable() is True

    def test_connect_error_means_off_aws(self) -> None:
        # Outside AWS the route doesn't exist → ConnectError.
        with patch.object(
            httpx.Client, "get",
            side_effect=httpx.ConnectError("no route"),
        ):
            assert _imds_is_reachable() is False

    def test_timeout_means_off_aws(self) -> None:
        # Firewalled / dropped → timeout.  Not a signal we're on AWS.
        with patch.object(
            httpx.Client, "get",
            side_effect=httpx.TimeoutException("timed out"),
        ):
            assert _imds_is_reachable() is False

    def test_os_error_treated_as_off_aws(self) -> None:
        # Lower-level socket failures (DNS, route unreachable) — same
        # treatment as timeout: treat as "not on AWS" rather than
        # crashing startup.
        with patch.object(
            httpx.Client, "get", side_effect=OSError("network unreachable"),
        ):
            assert _imds_is_reachable() is False


# ---------------------------------------------------------------------------
# Auth-enabled mode
# ---------------------------------------------------------------------------


class TestAuthEnabledMode:
    def test_complete_oidc_config_starts(self) -> None:
        # When auth is on, only the OIDC settings need to be present —
        # the disabled-mode guardrails (IMDS, bind, debug, ack) all
        # short-circuit.
        settings = Settings(
            auth_enabled=True,
            oidc_issuer="https://login.microsoftonline.com/tenant/v2.0",
            oidc_audience="api-client-id",
            # Disabled-mode-only settings can be at production defaults.
            debug=False,
            i_understand_auth_is_off="",
            bind_address="0.0.0.0",
        )
        run_startup_guardrails(settings)

    def test_missing_issuer_refuses(self) -> None:
        # Empty issuer would 401 every request with a confusing
        # signature error — surface it as a clear startup failure.
        settings = Settings(
            auth_enabled=True,
            oidc_issuer="",
            oidc_audience="api-client-id",
        )
        with pytest.raises(SystemExit) as exc:
            run_startup_guardrails(settings)
        assert "PK_OIDC_ISSUER" in str(exc.value)

    def test_missing_audience_refuses(self) -> None:
        settings = Settings(
            auth_enabled=True,
            oidc_issuer="https://example.com",
            oidc_audience="",
        )
        with pytest.raises(SystemExit) as exc:
            run_startup_guardrails(settings)
        assert "PK_OIDC_AUDIENCE" in str(exc.value)


# ---------------------------------------------------------------------------
# JWT algorithm allowlist (auth-enabled mode)
# ---------------------------------------------------------------------------


def _oidc_settings(**overrides) -> Settings:
    base = dict(
        auth_enabled=True,
        oidc_issuer="https://issuer.example.com",
        oidc_audience="api-client-id",
    )
    base.update(overrides)
    return Settings(**base)


class TestAllowedAlgorithms:
    def test_default_is_rs256(self) -> None:
        assert Settings().oidc_allowed_algorithms == ["RS256"]

    @pytest.mark.parametrize("algs", [
        ["RS256"], ["RS256", "PS256"], ["ES256", "ES384"], ["EdDSA"],
    ])
    def test_asymmetric_allowlists_start(self, algs) -> None:
        run_startup_guardrails(_oidc_settings(oidc_allowed_algorithms=algs))

    @pytest.mark.parametrize("bad", ["HS256", "HS512", "none", "rs256"])
    def test_symmetric_none_or_misspelled_refuses(self, bad) -> None:
        with pytest.raises(SystemExit) as exc:
            run_startup_guardrails(
                _oidc_settings(oidc_allowed_algorithms=["RS256", bad]),
            )
        assert "PK_OIDC_ALLOWED_ALGORITHMS" in str(exc.value)

    def test_empty_allowlist_refuses(self) -> None:
        with pytest.raises(SystemExit) as exc:
            run_startup_guardrails(_oidc_settings(oidc_allowed_algorithms=[]))
        assert "PK_OIDC_ALLOWED_ALGORITHMS" in str(exc.value)

    def test_env_var_json_format(self, monkeypatch) -> None:
        monkeypatch.setenv("PK_OIDC_ALLOWED_ALGORITHMS", '["RS256","ES256"]')
        assert Settings().oidc_allowed_algorithms == ["RS256", "ES256"]
