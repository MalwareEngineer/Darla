"""Startup guardrails for auth-disabled mode (RFC §16).

When ``PK_AUTH_ENABLED=false``, the application MUST refuse to start in
any environment that resembles production.  These checks run once at
app startup via :func:`run_startup_guardrails`; failures raise
:exc:`SystemExit` with a clear message so the operator can correct
the config and restart.

The combined effect (see RFC §16.3) is that running prod with auth off
requires deliberately overriding all six controls — which is sabotage,
not a footgun.

This module implements the four startup-time prevention controls.  The
remaining two live elsewhere:

* Hardcoded ``PK_AUTH_ENABLED=true`` in production Terraform (infra,
  not code — see ``darla-deployment/terraform/`` once it exists).
* Healthcheck unhealthy-when-disabled (``darla.api.health``).
* CRITICAL log per request (``darla.auth.middleware``).

The startup-time controls are:

1. **Required ack token** — ``PK_I_UNDERSTAND_AUTH_IS_OFF`` must equal
   the verbose constant string :const:`AUTH_OFF_ACK`.
2. **Localhost-only bind** — ``PK_BIND_ADDRESS`` must be ``127.0.0.1``,
   ``localhost`` or ``::1``.  This only means something because
   ``docker-compose.yml`` publishes the API on ``${PK_BIND_ADDRESS}``
   and injects that same value into the container; uvicorn itself
   listens on ``0.0.0.0`` *inside* the container network namespace,
   which is required for Docker port publishing to work at all.
   ``tests/test_auth/test_compose_exposure.py`` pins that wiring.
3. **No AWS IMDS** — refuse to start if the EC2 instance metadata
   service responds (i.e. we're on AWS).
4. **Debug mode required** — ``PK_DEBUG`` must be ``True``.
"""

from __future__ import annotations

import logging
import sys
from typing import NoReturn

import httpx

from darla.config import Settings, get_settings


# Verbose enough that nobody types this by accident or copies it
# without noticing what it claims.  The string is part of the public
# config contract — changing it will break existing dev environments.
AUTH_OFF_ACK = "yes-only-for-local-eval"

# Which bind addresses we'll allow with auth disabled.  ``0.0.0.0`` is
# explicitly NOT here — that's the prod default and the most common
# way someone exposes a "dev" container to the network by accident.
_LOCALHOST_VALUES = frozenset({"127.0.0.1", "localhost", "::1"})

# JWT algorithms an OIDC IdP can legitimately sign with (JWKS publishes
# public keys, so only asymmetric schemes make sense).  Validated
# against ``PK_OIDC_ALLOWED_ALGORITHMS`` when auth is enabled.
ASYMMETRIC_JWT_ALGORITHMS = frozenset({
    "RS256", "RS384", "RS512",
    "PS256", "PS384", "PS512",
    "ES256", "ES384", "ES512",
    "EdDSA",
})

# AWS instance metadata service.  IMDSv2 requires a token-fetch step,
# but IMDSv1 plus IMDSv2 both respond on this URL — a 200 from this
# endpoint is unambiguous "we're on AWS".  Outside AWS the connection
# either refuses (no route) or hangs (firewalled), so the timeout is
# our actual signal.
_IMDS_URL = "http://169.254.169.254/latest/meta-data/"
_IMDS_TIMEOUT_SECONDS = 0.2

logger = logging.getLogger(__name__)


def run_startup_guardrails(settings: Settings | None = None) -> None:
    """Validate the auth configuration at startup; ``SystemExit`` on failure.

    Safe to call multiple times.  When ``auth_enabled=True`` this is
    almost a no-op — only checks that ``oidc_issuer`` and
    ``oidc_audience`` are set, since validation against an empty
    issuer would 401 every request with a confusing error.
    """
    s = settings if settings is not None else get_settings()

    if s.auth_enabled:
        _enforce_oidc_settings_present(s)
        logger.info("Auth ENABLED — OIDC issuer=%s", s.oidc_issuer)
        return

    # Disabled-mode path — every guardrail must pass.
    _enforce_ack_token(s)
    _enforce_localhost_bind(s)
    _enforce_debug_mode(s)
    _enforce_not_on_aws()

    logger.critical(
        "AUTH DISABLED — running in community / local-evaluation mode. "
        "All guardrails passed (ack token set, localhost bind, debug "
        "mode, not on AWS).  This deployment will accept all requests "
        "without authentication.",
    )


def _enforce_oidc_settings_present(s: Settings) -> None:
    if not s.oidc_issuer:
        _die("PK_AUTH_ENABLED=true but PK_OIDC_ISSUER is empty")
    if not s.oidc_audience:
        _die("PK_AUTH_ENABLED=true but PK_OIDC_AUDIENCE is empty")
    if not s.oidc_allowed_algorithms:
        _die("PK_AUTH_ENABLED=true but PK_OIDC_ALLOWED_ALGORITHMS is empty")
    bad = [a for a in s.oidc_allowed_algorithms if a not in ASYMMETRIC_JWT_ALGORITHMS]
    if bad:
        _die(
            f"PK_OIDC_ALLOWED_ALGORITHMS contains {bad!r}; only asymmetric "
            f"algorithms are accepted ({sorted(ASYMMETRIC_JWT_ALGORITHMS)}).  "
            "An OIDC IdP signs with its private key and publishes the "
            "public half via JWKS — an HMAC or 'none' entry would let "
            "anyone holding the public key mint tokens.",
        )


def _enforce_ack_token(s: Settings) -> None:
    if s.i_understand_auth_is_off != AUTH_OFF_ACK:
        _die(
            "PK_AUTH_ENABLED=false requires PK_I_UNDERSTAND_AUTH_IS_OFF="
            f"{AUTH_OFF_ACK!r}.  This is intentionally verbose to "
            "prevent accidental disablement — set it explicitly if "
            "you really want to run without authentication.",
        )


def _enforce_localhost_bind(s: Settings) -> None:
    addr = s.bind_address.strip().lower()
    if addr not in _LOCALHOST_VALUES:
        _die(
            f"PK_AUTH_ENABLED=false but PK_BIND_ADDRESS={s.bind_address!r}; "
            f"must be one of {sorted(_LOCALHOST_VALUES)} when auth is "
            "disabled.  Disabled-mode deployments must not be reachable "
            "from the network.",
        )


def _enforce_debug_mode(s: Settings) -> None:
    if not s.debug:
        _die(
            "PK_AUTH_ENABLED=false but PK_DEBUG=false.  Disabled-mode "
            "deployments must run with PK_DEBUG=true — production-shaped "
            "configurations (debug off) are not permitted to skip auth.",
        )


def _enforce_not_on_aws() -> None:
    """Probe AWS instance metadata service; refuse to start if reachable."""
    if _imds_is_reachable():
        _die(
            "PK_AUTH_ENABLED=false but AWS IMDS is reachable — refusing "
            "to start in a probable production environment.  If this is "
            "a false positive (e.g. a developer VM with the metadata "
            "address bound), block 169.254.169.254 outbound.",
        )


def _imds_is_reachable() -> bool:
    """Return True if AWS IMDS responds within the timeout.

    Any non-error response counts as "reachable" — IMDSv1 returns 200
    on the listing endpoint; IMDSv2 returns 401 (token required) which
    *also* tells us we're on AWS.  Connection errors / timeouts → not
    on AWS.

    Kept synchronous so it can run during ``create_app`` before the
    event loop is fully wired.  Using ``httpx.Client`` rather than
    ``socket`` so the same library mocks work in tests.
    """
    try:
        with httpx.Client(timeout=_IMDS_TIMEOUT_SECONDS) as client:
            resp = client.get(_IMDS_URL)
            # 200, 401 (IMDSv2 challenge), 403 (forbidden but reachable) all
            # indicate "on AWS".  500-class would also count.  Only network
            # errors mean "not on AWS" — and those raise, handled below.
            return 0 < resp.status_code < 600
    except httpx.HTTPError:
        return False
    except OSError:
        # Lower-level socket / DNS / route failures.
        return False


def _die(message: str) -> NoReturn:
    logger.critical(message)
    raise SystemExit(f"[guardrail] {message}")
