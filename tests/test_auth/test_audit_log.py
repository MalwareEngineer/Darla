"""AuditLogMiddleware — RFC 0001 Phase 5 behavior contract.

The middleware writes one row per request to the ``audit_log`` table.
These tests pin every load-bearing behavior:

* successful requests, failed-auth requests, and exceptions all log
* disabled-mode requests log with NULL actor + auth_mode='disabled'
* ``/api/v1/health`` is skipped (LB noise)
* ``X-Request-ID`` is attached to every audited response
* ``set_audit_extra`` data flows through to ``AuditLog.extra``
* audit-write failures don't break the request

The tests stand up an in-memory SQLite database, patch the audit
middleware's ``async_session_factory`` to point at it, and drive a
real FastAPI app via ``httpx.AsyncClient`` so we exercise the full
ASGI middleware pipeline.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest
from fastapi import FastAPI, HTTPException, Request
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from darla.auth import AuditLogMiddleware, set_audit_extra
from darla.models import AUTH_MODE_DISABLED, AUTH_MODE_OIDC, AuditLog, Base

# ---------------------------------------------------------------------------
# Async SQLite harness — fresh DB per test, patched into the audit module.
# ---------------------------------------------------------------------------


@pytest.fixture
async def audit_db():
    """Set up an in-memory async SQLite with just the AuditLog table
    created, and patch the audit module to use it.

    Returns a sessionmaker the test can use to query rows back out.
    """
    pytest.importorskip("aiosqlite")
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all, tables=[AuditLog.__table__])
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    # The middleware imports async_session_factory from darla.database.
    # Patch the attribute on the audit module so writes land in our
    # in-memory SQLite, not the real Postgres.
    with patch("darla.auth.audit.async_session_factory", factory):
        yield factory

    await engine.dispose()


def _build_app(*, auth_enabled: bool) -> FastAPI:
    """Construct a minimal FastAPI app with the audit middleware and
    a few representative routes — no router.py / api imports needed.
    """
    from darla.config import get_settings

    # The middleware reads ``settings.auth_enabled`` at request time
    # to choose default auth_mode.  Patching attribute on the cached
    # settings instance is cheaper than rebuilding it.
    get_settings().auth_enabled = auth_enabled

    app = FastAPI()
    app.add_middleware(AuditLogMiddleware)

    # All handler return types use ``dict`` (not ``dict[str, str]``)
    # so FastAPI doesn't refuse non-string values like nested lists.
    @app.get("/api/v1/kits")
    async def list_kits(request: Request) -> dict:
        # Simulate a handler that also recorded who was attached
        # by the (not-installed-in-this-test-app) current_user dep.
        request.state.actor_subject = "subject-abc"
        request.state.actor_upn = "alice@example.com"
        return {"status": "ok"}

    @app.get("/api/v1/health")
    async def health() -> dict:
        return {"status": "ok"}

    @app.get("/api/v1/victims")
    async def list_victims(request: Request) -> dict:
        set_audit_extra(request, victim_ids=["v-1", "v-2"])
        return {"items": ["v-1", "v-2"]}

    @app.get("/api/v1/boom")
    async def boom() -> dict:
        raise HTTPException(status_code=418, detail="teapot")

    @app.get("/api/v1/crash")
    async def crash() -> dict:
        raise RuntimeError("handler exploded")

    return app


async def _all_rows(factory) -> list[AuditLog]:
    async with factory() as s:
        result = await s.scalars(select(AuditLog))
        return list(result)


# ---------------------------------------------------------------------------
# Happy path — authenticated request writes a row, attaches request_id.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_logs_authenticated_request(audit_db) -> None:
    app = _build_app(auth_enabled=True)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        resp = await c.get("/api/v1/kits")

    assert resp.status_code == 200
    # request_id is attached to every audited response — clients can
    # quote it in support requests to grep audit_log directly.
    assert "X-Request-ID" in resp.headers
    request_id = resp.headers["X-Request-ID"]

    rows = await _all_rows(audit_db)
    assert len(rows) == 1
    row = rows[0]
    assert row.method == "GET"
    assert row.path == "/api/v1/kits"
    assert row.status_code == 200
    assert row.actor_subject == "subject-abc"  # set by the stub handler
    assert row.actor_upn == "alice@example.com"
    assert row.auth_mode == AUTH_MODE_OIDC
    assert row.request_id == request_id
    assert row.response_ms >= 0


# ---------------------------------------------------------------------------
# Disabled-mode logging — NULL actor, auth_mode='disabled' (RFC §16.1).
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_logs_disabled_mode_with_null_actor(audit_db) -> None:
    # Build app fresh in disabled mode.  Don't reach into a handler
    # that pretends to be authenticated — let the middleware's defaults
    # win.
    from darla.config import get_settings

    get_settings().auth_enabled = False

    app = FastAPI()
    app.add_middleware(AuditLogMiddleware)

    @app.get("/api/v1/anything")
    async def anything() -> dict:
        return {"ok": True}

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        resp = await c.get("/api/v1/anything")

    assert resp.status_code == 200
    rows = await _all_rows(audit_db)
    assert len(rows) == 1
    assert rows[0].actor_subject is None
    assert rows[0].actor_upn is None
    assert rows[0].auth_mode == AUTH_MODE_DISABLED


# ---------------------------------------------------------------------------
# Failed-auth requests are still audited (NULL actor, status 401).
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_logs_failed_auth_request(audit_db) -> None:
    from darla.config import get_settings

    get_settings().auth_enabled = True

    app = FastAPI()
    app.add_middleware(AuditLogMiddleware)

    @app.get("/api/v1/protected")
    async def protected() -> dict:
        # Simulate the auth dep raising 401 before populating state.
        raise HTTPException(status_code=401, detail="Missing Bearer token")

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        resp = await c.get("/api/v1/protected")

    assert resp.status_code == 401
    rows = await _all_rows(audit_db)
    assert len(rows) == 1
    # An anonymous attacker probing the API still leaves fingerprints.
    assert rows[0].status_code == 401
    assert rows[0].actor_subject is None
    assert rows[0].auth_mode == AUTH_MODE_OIDC  # default for auth-on
    assert rows[0].path == "/api/v1/protected"


# ---------------------------------------------------------------------------
# Skip /health to avoid LB noise.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_skips_health_endpoint(audit_db) -> None:
    app = _build_app(auth_enabled=True)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        await c.get("/api/v1/health")
        await c.get("/api/v1/health")
        await c.get("/api/v1/health")
        # And a non-skipped path for contrast.
        await c.get("/api/v1/kits")

    rows = await _all_rows(audit_db)
    assert len(rows) == 1
    assert rows[0].path == "/api/v1/kits"
    # No /health rows — load-balancer noise must not flood audit_log.
    assert all("health" not in r.path for r in rows)


# ---------------------------------------------------------------------------
# set_audit_extra flows through to JSONB column.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_audit_extra_persists(audit_db) -> None:
    app = _build_app(auth_enabled=True)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        await c.get("/api/v1/victims")

    rows = await _all_rows(audit_db)
    assert len(rows) == 1
    # Victim-PII routes record IDs returned for "who saw which
    # victims" reports (RFC §5.2).
    assert rows[0].extra == {"victim_ids": ["v-1", "v-2"]}


def test_set_audit_extra_merges_multiple_calls() -> None:
    """Calling ``set_audit_extra`` more than once in a handler should
    merge keys, not overwrite — so handlers can build up the extra
    payload incrementally as they discover what's worth logging."""

    class _State:
        audit_extra: Any = None

    class _Request:
        state = _State()

    req = _Request()

    set_audit_extra(req, victim_ids=["v-1"])  # type: ignore[arg-type]
    set_audit_extra(req, source="pipeline", count=5)  # type: ignore[arg-type]

    assert req.state.audit_extra == {
        "victim_ids": ["v-1"],
        "source": "pipeline",
        "count": 5,
    }


# ---------------------------------------------------------------------------
# Handler exceptions still produce an audit row.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_logs_http_exception(audit_db) -> None:
    app = _build_app(auth_enabled=True)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        resp = await c.get("/api/v1/boom")

    assert resp.status_code == 418
    rows = await _all_rows(audit_db)
    assert len(rows) == 1
    assert rows[0].status_code == 418
    # Even error responses get a request_id so users can quote it.
    assert "X-Request-ID" in resp.headers


# ---------------------------------------------------------------------------
# Audit write failure must NOT break the request.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_audit_failure_is_swallowed() -> None:
    """If the DB is briefly unreachable, the request must still succeed
    — a missing audit row is recoverable; a 500 served because audit
    broke is not.  Patches the session factory to raise."""
    from darla.config import get_settings

    get_settings().auth_enabled = True

    app = FastAPI()
    app.add_middleware(AuditLogMiddleware)

    @app.get("/api/v1/anything")
    async def anything() -> dict:
        return {"ok": True}

    def _broken_factory():
        raise RuntimeError("database is on fire")

    with patch("darla.auth.audit.async_session_factory", _broken_factory):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://t",
        ) as c:
            resp = await c.get("/api/v1/anything")

    # Request succeeded despite the broken audit path — exactly the
    # contract we promise.
    assert resp.status_code == 200
    assert "X-Request-ID" in resp.headers
