"""Auth middleware — bearer-token validation, JIT user provisioning,
role enforcement, and the disabled-mode CRITICAL request log.

Public surface:

* :func:`current_user` — FastAPI dependency.  Returns the authenticated
  :class:`darla.models.User` when ``auth_enabled=True``, ``None`` when
  ``auth_enabled=False``.  All handlers that take this dependency must
  tolerate ``None``.
* :func:`require_role` — dependency factory that gates handlers on a
  minimum :class:`darla.models.UserRole`.  No-op when auth is disabled.
* :class:`DisabledAuthLoggingMiddleware` — Starlette middleware that
  emits a CRITICAL log line per request when auth is disabled (RFC
  §16 guardrail #6).

Phase 2 ships these dependencies but does NOT yet apply them to any
existing routers — that's Phase 4.  The middleware exists so Phase 3
(frontend wiring) and Phase 4 (router decoration) have something to
import; until Phase 4, everything still serves anonymously even with
auth enabled.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, Request, status
from jwt import PyJWK, PyJWTError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from darla.auth.claims import claim_to_role_strings, resolve_claim_path
from darla.auth.jwks import get_signing_key
from darla.config import get_settings
from darla.database import get_db
from darla.models import User, UserRole

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Token validation + JIT user provisioning
# ---------------------------------------------------------------------------


async def current_user(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> User | None:
    """Resolve the authenticated user from the bearer token.

    * ``auth_enabled=False``: returns ``None``.  Sets
      ``request.state.auth_mode = "disabled"`` for the audit middleware
      (Phase 5) to read.
    * ``auth_enabled=True``: validates the ``Authorization: Bearer <jwt>``
      header against the configured OIDC issuer/audience, JIT-creates
      the User row on first sight, refreshes display fields and role
      on every login, and rejects 401/403 on any failure.

    Reads/writes ``request.state``:

      * ``auth_mode`` — ``"oidc"`` or ``"disabled"``
      * ``actor_subject`` — the OIDC subject (None in disabled mode)
      * ``actor_upn`` — token's preferred_username (None in disabled mode)
    """
    settings = get_settings()

    if not settings.auth_enabled:
        request.state.auth_mode = "disabled"
        request.state.actor_subject = None
        request.state.actor_upn = None
        return None

    request.state.auth_mode = "oidc"

    # ── 1. Extract bearer token ──────────────────────────────────────
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Missing Bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = auth_header.removeprefix("Bearer ").strip()

    # ── 2. Validate signature, iss, aud, exp ─────────────────────────
    try:
        unverified_header = jwt.get_unverified_header(token)
    except PyJWTError as e:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, f"Malformed token: {e}",
        ) from e

    # The header's ``alg`` is attacker-controlled — check it against the
    # server-side allowlist before it can pick a verification scheme.
    alg = unverified_header.get("alg")
    if alg not in settings.oidc_allowed_algorithms:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            f"Token algorithm {alg!r} not allowed",
        )

    kid = unverified_header.get("kid")
    if not kid:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "Token header missing kid",
        )

    try:
        key = await get_signing_key(kid)
    except Exception as e:
        # JWKS errors get logged as warnings (potential IdP issue) but
        # surfaced to the client as a generic 401 — never leak internals.
        logger.warning("JWKS lookup failed for kid=%s: %s", kid, e)
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "Token signing key not found",
        ) from e

    # A JWK that declares its own ``alg`` is pinned to it (RFC 7517 §4.4).
    key_alg = key.get("alg")
    if key_alg and key_alg != alg:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            f"Token algorithm {alg!r} does not match signing key ({key_alg!r})",
        )

    try:
        claims = jwt.decode(
            token,
            PyJWK(key, algorithm=alg),
            algorithms=settings.oidc_allowed_algorithms,
            audience=settings.oidc_audience,
            issuer=settings.oidc_issuer,
            options={"require": ["exp", "iss", "aud"]},
        )
    except PyJWTError as e:
        # PyJWTError is the root of every PyJWT failure — including key
        # construction (PyJWKError) when the key type doesn't fit the
        # algorithm, which python-jose raised outside its JWTError tree.
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, f"Invalid token: {e}",
        ) from e

    # ── 3. Extract subject + role ────────────────────────────────────
    subject = resolve_claim_path(claims, settings.oidc_subject_claim)
    if not subject or not isinstance(subject, str):
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            f"Token missing subject claim {settings.oidc_subject_claim!r}",
        )

    role_strings = claim_to_role_strings(
        resolve_claim_path(claims, settings.oidc_role_claim),
    )
    role = _map_role(role_strings, settings.oidc_viewer_role_value,
                     settings.oidc_analyst_role_value)
    if role is None:
        # Per RFC §3 decision #6 — "logged in" ≠ "authorized".  Forces
        # IT to assign a group rather than silently defaulting users
        # to viewer.
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "No app role assigned in OIDC token",
        )

    # ── 4. JIT upsert User row ───────────────────────────────────────
    upn = str(claims.get("preferred_username") or claims.get("upn") or "")
    display_name = str(claims.get("name") or upn or subject)
    now = datetime.now(UTC)

    user = await db.scalar(select(User).where(User.oidc_subject == subject))
    if user is None:
        user = User(
            oidc_subject=subject,
            upn=upn,
            display_name=display_name,
            role=role,
            last_login_at=now,
        )
        db.add(user)
        # Flush so subsequent queries inside the same request see the row;
        # commit happens at end of request via the dep's session lifecycle.
        await db.flush()
    else:
        user.role = role
        user.upn = upn or user.upn
        user.display_name = display_name or user.display_name
        user.last_login_at = now

    await db.commit()

    # ── 5. Local kill switch ─────────────────────────────────────────
    if user.disabled_at is not None:
        # Distinct from the IdP-side disablement which can lag up to ~1h
        # for token refresh.  CLI-set; cleared with `darla-admin user enable`.
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "User disabled locally",
        )

    # Stash audit context for Phase 5's audit middleware.
    request.state.actor_subject = user.oidc_subject
    request.state.actor_upn = user.upn

    return user


def _map_role(
    role_strings: list[str],
    viewer_value: str,
    analyst_value: str,
) -> UserRole | None:
    """Map the IdP role-claim values to a :class:`UserRole`.

    Picks Analyst over Viewer when both are present (you can't be
    "less than" an Analyst once granted).  Returns ``None`` when the
    user has neither — middleware turns that into a 403.

    Comparison is case-sensitive — match the IdP's exact assignment
    string.  If a deployment uses lowercase values like "darla.viewer",
    the operator sets ``PK_OIDC_VIEWER_ROLE_VALUE`` to match.
    """
    has_analyst = analyst_value in role_strings
    has_viewer = viewer_value in role_strings
    if has_analyst:
        return UserRole.ANALYST
    if has_viewer:
        return UserRole.VIEWER
    return None


# ---------------------------------------------------------------------------
# Role enforcement
# ---------------------------------------------------------------------------


def require_role(min_role: UserRole):
    """Dependency factory — gate a handler on minimum :class:`UserRole`.

    No-op in disabled mode (returns ``None``).  When auth is enabled,
    raises 403 if the user's :attr:`User.effective_role` is below
    ``min_role``.  Always read ``effective_role`` (NOT ``role``) so
    the CLI ``role_override`` is honored.

    Example::

        @router.post("/kits/{id}/reanalyze")
        async def reanalyze(
            id: UUID,
            user: User = Depends(require_role(UserRole.ANALYST)),
        ):
            ...
    """

    async def _dep(
        user: Annotated[User | None, Depends(current_user)],
    ) -> User | None:
        # Disabled-mode bypass.  Safe because guardrails enforce
        # localhost-only bind in this mode (RFC §16).
        if user is None:
            return None

        effective = user.effective_role
        # Two-tier lattice: ANALYST > VIEWER.  Analyst satisfies any
        # viewer-only requirement automatically.
        if min_role == UserRole.ANALYST and effective != UserRole.ANALYST:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"Role {min_role.value!r} required (have {effective.value!r})",
            )
        # No need to check VIEWER — any authenticated user has at least
        # one role assignment by the time current_user returns.
        return user

    return _dep


# ---------------------------------------------------------------------------
# Disabled-mode request logging (RFC §16 guardrail #6)
# ---------------------------------------------------------------------------


class DisabledAuthLoggingMiddleware(BaseHTTPMiddleware):
    """ASGI middleware — emits a CRITICAL log per request when auth is off.

    The log line is engineered to be alertable: every line contains
    the literal string ``"AUTH DISABLED"`` so a CloudWatch metric
    filter can match on it without regex.  Includes client IP and
    request path for forensic context — query strings are excluded
    because they can carry PII or secrets we don't want in the log
    stream.

    No-op when auth is enabled.

    The companion audit-log row (Phase 5) will write to the database;
    this middleware only handles the structured-log half.
    """

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next):
        if get_settings().auth_enabled:
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        # Single line, alert-friendly format.  Path-only (no query
        # string) keeps PII / tokens out of the log stream.
        logger.critical(
            "AUTH DISABLED — request from %s to %s %s",
            client_ip, request.method, request.url.path,
        )
        return await call_next(request)
